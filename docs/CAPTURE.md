# What to capture from the council portal

All of the council calls the app makes are wired up and working; this doc is the
re-capture guide for when the council changes its portal (an API-shape change
shows up as `FailUnexpected` operator alerts). Capture the calls below from a
real, logged-in browser session to compare against `internal/parking`.

## Easiest: one HAR file

In Firefox/Chrome DevTools → **Network**, tick **Persist Logs**, then:

1. Log in to the portal from scratch.
2. **Change the allocated vehicle** on your permit to a different plate (this is
   the critical one).
3. Navigate to the page that lists your permit's vehicles.

Then right-click the Network panel → **Save All As HAR** and hand it over.

> A HAR contains live tokens and cookies. Fine to share privately; don't post it
> anywhere public. The refresh token is the durable secret, treat it carefully.

## Or: individual requests

Right-click each relevant request → **Copy → Copy as cURL**:

- **The plate change**, every request fired when you submit the change. Likely a
  `POST`/`PUT` under `/ssp-svc/api/permits/...`. We need method, full URL, and the
  **request body**.
- **`vehicleGridView`**, `POST /ssp-svc/api/permits/vehicleGridView?permitID=..&fkPermitTypeID=..`;
  we need the **request body** (~38 bytes) and the **response JSON**.
- **The login token exchange**, `POST …/idm/connect/token`. Confirms whether a
  `refresh_token` is issued and which `scope`/`redirect_uri` are in play (this
  resolves the "known open risk" in the README).

## What each answers

| Capture | Fills in | Resolves |
|---|---|---|
| Plate-change request | `parking.SetVehicle` | the core feature |
| `vehicleGridView` req/resp | `parking.CurrentVehicle` | showing/confirming current plate |
| `/connect/token` response | link flow assumptions | whether refresh tokens + our redirect URI work |
