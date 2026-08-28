# Provider target options

Provider-specific values live in `PublishTarget.options`; secrets never do.

## Eventbrite

`currency`, `ticket_name`, `quantity_total`, `free`, and for paid tickets
`cost_minor`. The connected account key is the Eventbrite organization ID.

## Meetup

`group_urlname`, `venue_id`, and `publish_status` (`DRAFT` or `PUBLISHED`).

## Meta Facebook Page

`message`. The connected account key is the Page ID, and the encrypted token
envelope contains the Page access token.

## Craigslist

`posting_url` is optional. The adapter emits `action_required` and prepared
fields, and never submits a post.

## Generic webhook

`endpoint` must be HTTPS. The connection token is used only as an HMAC-SHA256
signing secret.
