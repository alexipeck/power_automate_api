# power_automate_api
Intended to be used behind NGINX with it providing HTTPS with proxy to localhost:2458
Clients sending an invalid API key will receive 401 UNAUTHORIZED and 'null' in body as response.

POST to /generic/filter_by_exclusions with body:
{
    api_key: string,
    strings: string[],
    exclusions: string[],
}
Will receive:
{
    filtered_messages: string[],
}

POST to /cipp/parse_messages_from_email_alert_body with body:
{
    pub api_key: string,
    pub body: string,
    pub domain_exclusions: string[],
}
Will receive, with error_messages containing potentially one error message per skipped entry:
{
    filtered_messages: string[],
    error_messages: string[],
}