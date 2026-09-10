Update TeamCity resources using JSON bodies on endpoints that accept JSON. For example, path `buildQueue/pausedState` and body `{"paused":true,"reason":"Maintenance"}`. Endpoints requiring raw text or XML bodies are not supported by this tool.

Generic `PUT` against the TeamCity REST API. Paths may be relative (`projects`) or include `/app/rest/` (`/app/rest/projects`); the prefix is added when absent. Configure `TEAMCITY_URL` as the server URL, including any context path but excluding `/app/rest`, and `TEAMCITY_TOKEN` as a personal access token.

Returns TOON by default; use `outputFormat: "json"` for JSON and `jq` for JMESPath filtering. Pass TeamCity `locator` and `fields` through `queryParams`. Pagination is explicit: follow `nextHref` using another call; results are not automatically aggregated.

API reference: https://www.jetbrains.com/help/teamcity/rest/teamcity-rest-api-documentation.html
