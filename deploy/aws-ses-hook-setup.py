#!/usr/bin/env python3
"""Wire SES bounce/complaint events into p.stonn's suppression list.

p.stonn stops emailing an address once the provider tells us it is dead (a hard
bounce) or that the recipient complained. Without this, the app keeps sending to
a black hole: the user never learns their guest's address was a typo, and the
repeated hard bounces are what get a sending domain's reputation destroyed and,
on SES, its sending paused.

This script is ADDITIVE and idempotent. It:

  * finds (or creates) the SNS topic that carries the domain's SES events
  * subscribes the app's HTTPS webhook (https://<host>/hooks/ses) to it
  * ensures a configuration set emits BOUNCE + COMPLAINT to that topic, and is
    the identity default so every send is covered

If you already ran the fleet's scripts/aws-ses-setup.py (SES identity, DKIM,
SMTP user, and a bounce->Lambda->ntfy operator alert), point this at the SAME
topic name: the Lambda keeps alerting you, and this adds the app as a second
subscriber. Neither replaces the other — the Lambda tells the operator, the
webhook teaches the app.

Requires boto3 and AWS credentials:
    pip install boto3
    python3 deploy/aws-ses-hook-setup.py \
      --profile my-admin --region ap-southeast-2 \
      --domain stonn.org --app-url https://p.stonn.org

RUN IT TWICE. SNS confirms an HTTPS subscription by POSTing to the endpoint, and
the app only accepts a confirmation once it knows the topic ARN. So:

  pass 1  creates the topic and prints SES_SNS_TOPIC_ARN
          -> add it to the app's .env and redeploy
  pass 2  creates the subscription; the running app confirms it automatically

Pass 1 stops before subscribing if it can see the app is not configured yet.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    sys.exit("boto3 required: pip install boto3")

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BOLD = "\033[1m"
RESET = "\033[0m"


def ok(message: str) -> None:
    print(f"  {GREEN}✓{RESET} {message}")


def skip(message: str) -> None:
    print(f"  · {message}")


def warn(message: str) -> None:
    print(f"  {YELLOW}!{RESET} {message}")


def fail(message: str) -> None:
    print(f"  {RED}✗{RESET} {message}")


def section(title: str) -> None:
    print(f"\n{BOLD}{title}{RESET}")


def probe_hook(app_url: str) -> str:
    """Report whether the app's webhook is live: 'ready', 'unconfigured', or 'unreachable'.

    The endpoint is only registered when SES_SNS_TOPIC_ARN is set, so a 404 means
    the env var has not reached the container yet. An unsigned POST is refused
    (400/403) when it IS configured — which is exactly the signal we want, and
    costs nothing since the request carries no valid signature.
    """
    url = app_url.rstrip("/") + "/hooks/ses"
    req = urllib.request.Request(url, data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:  # DNS, TLS, connection refused
        warn(f"could not reach {url}: {e}")
        return "unreachable"
    if code == 404:
        return "unconfigured"
    if code in (400, 403):
        return "ready"
    warn(f"{url} answered {code}; expected 400/403 (configured) or 404 (not configured)")
    return "unreachable"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile")
    ap.add_argument("--region", default="ap-southeast-2")
    ap.add_argument("--domain", required=True, help="the SES sending domain, e.g. stonn.org")
    ap.add_argument("--app-url", required=True, help="public base URL of the app, e.g. https://p.stonn.org")
    ap.add_argument("--sns-topic", default=None, help="SNS topic name (default <slug>-ses-events, matching aws-ses-setup.py)")
    ap.add_argument("--config-set", default=None, help="configuration set (default <slug>-events)")
    ap.add_argument("--force-subscribe", action="store_true",
                    help="subscribe even if the app's webhook looks unconfigured")
    args = ap.parse_args()

    slug = args.domain.replace(".", "-")
    topic_name = args.sns_topic or f"{slug}-ses-events"
    cs_name = args.config_set or f"{slug}-events"
    endpoint = args.app_url.rstrip("/") + "/hooks/ses"

    if not args.app_url.startswith("https://"):
        sys.exit("--app-url must be https: SNS will not deliver to a plaintext endpoint")

    s = boto3.Session(profile_name=args.profile, region_name=args.region)
    acct = s.client("sts").get_caller_identity()["Account"]
    sns, ses = s.client("sns"), s.client("sesv2")
    print(f"account={acct} region={args.region} domain={args.domain}")
    print(f"topic={topic_name} config-set={cs_name}\nendpoint={endpoint}")

    # 1) SNS topic. CreateTopic is idempotent and returns the existing ARN.
    section("SNS topic")
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ok(f"{topic_arn}")
    # Let SES publish to it (no-op if aws-ses-setup.py already set this).
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowSESPublish",
            "Effect": "Allow",
            "Principal": {"Service": "ses.amazonaws.com"},
            "Action": "sns:Publish",
            "Resource": topic_arn,
            "Condition": {"StringEquals": {"AWS:SourceAccount": acct}},
        }],
    }
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy",
                             AttributeValue=json.dumps(policy))
    ok("topic policy allows ses.amazonaws.com to publish")

    # Sign notifications with SHA-256 (SignatureVersion 2) rather than the SHA-1
    # default. The webhook verifies whatever the message claims to be signed with, so
    # while the topic emits version 1 the endpoint's trust rests on SHA-1 over a
    # payload that includes remote-influenced text (a bounce's diagnostic code comes
    # from the receiving mail server).
    #
    # The app now accepts ONLY version 2. That is safe because this attribute is set
    # here and on the live topic; it was not safe before, since refusing v1 on a topic
    # that still spoke it would have silently stopped all bounce and complaint
    # processing, and an app that stops learning about dead addresses keeps mailing
    # them until the sending domain is blacklisted. If you create a NEW topic, this
    # step is required before the webhook will accept anything from it.
    try:
        sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="SignatureVersion",
                                 AttributeValue="2")
        ok("topic signs with SHA-256 (SignatureVersion 2)")
    except Exception as exc:  # older regions/endpoints may not accept the attribute
        fail(f"could not set SignatureVersion=2 ({exc}). The app accepts only version 2, "
             "so bounce and complaint events from this topic would all be refused.")

    # 2) Configuration set emitting BOUNCE + COMPLAINT, set as the identity
    #    default so every send from this domain is covered with no app change.
    section("SES configuration set")
    try:
        ses.create_configuration_set(ConfigurationSetName=cs_name)
        ok("created")
    except ClientError as e:
        if e.response["Error"]["Code"] != "AlreadyExistsException":
            raise
        skip("exists")
    dest = {"SnsDestination": {"TopicArn": topic_arn},
            "Enabled": True,
            "MatchingEventTypes": ["BOUNCE", "COMPLAINT"]}
    try:
        ses.create_configuration_set_event_destination(
            ConfigurationSetName=cs_name, EventDestinationName="to-sns", EventDestination=dest)
        ok("event destination to-sns -> BOUNCE, COMPLAINT")
    except ClientError as e:
        if e.response["Error"]["Code"] != "AlreadyExistsException":
            raise
        ses.update_configuration_set_event_destination(
            ConfigurationSetName=cs_name, EventDestinationName="to-sns", EventDestination=dest)
        ok("event destination to-sns updated -> BOUNCE, COMPLAINT")
    try:
        ses.put_email_identity_configuration_set_attributes(
            EmailIdentity=args.domain, ConfigurationSetName=cs_name)
        ok(f"{cs_name} is the default configuration set for {args.domain}")
    except ClientError as e:
        warn(f"could not set the identity default ({e.response['Error']['Code']}); "
             f"sends will only emit events if they name the configuration set")

    # 3) The app's HTTPS subscription.
    section("App webhook subscription")
    existing = None
    paginator = sns.get_paginator("list_subscriptions_by_topic")
    for page in paginator.paginate(TopicArn=topic_arn):
        for sub in page["Subscriptions"]:
            if sub["Protocol"] == "https" and sub["Endpoint"] == endpoint:
                existing = sub
                break
    if existing and existing["SubscriptionArn"].startswith("arn:"):
        ok(f"already subscribed and confirmed ({existing['SubscriptionArn'].rsplit(':', 1)[-1]})")
        print_env(topic_arn)
        print(f"\n{GREEN}Done.{RESET}")
        return
    if existing:
        skip("a subscription exists but is still PendingConfirmation")

    state = probe_hook(args.app_url)
    if state == "unconfigured" and not args.force_subscribe:
        warn("the app is running but its webhook is NOT enabled yet (it answered 404).")
        print_env(topic_arn)
        print(f"\n{YELLOW}Next:{RESET} add that line to the app's .env, redeploy, then re-run this script.")
        print("      (SNS confirms by POSTing to the app, and the app only accepts a")
        print("       confirmation for a topic ARN it has been told about.)")
        return
    if state == "unreachable" and not args.force_subscribe:
        fail("could not confirm the app is reachable; re-run once it is, or pass --force-subscribe")
        print_env(topic_arn)
        return

    sub = sns.subscribe(TopicArn=topic_arn, Protocol="https", Endpoint=endpoint,
                        ReturnSubscriptionArn=True)
    ok("subscription requested; SNS is POSTing the confirmation to the app now")

    # Confirmation is handled by the running app, usually within a second.
    for _ in range(10):
        time.sleep(2)
        arn = sns.get_subscription_attributes(
            SubscriptionArn=sub["SubscriptionArn"])["Attributes"].get("PendingConfirmation")
        if arn == "false":
            ok("confirmed by the app")
            break
    else:
        warn("still pending after 20s — check the app logs for 'ses hook'")

    print_env(topic_arn)
    print(f"\n{GREEN}Done.{RESET} Bounces and complaints now reach the app's suppression list;")
    print("      see them under 'Undeliverable addresses' on /admin.")


def print_env(topic_arn: str) -> None:
    section("Add to the app's .env")
    print(f"SES_SNS_TOPIC_ARN={topic_arn}")


if __name__ == "__main__":
    main()
