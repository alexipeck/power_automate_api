use regex::Regex;

const TABLE_ROW_PATTERN: &str = r"<tr>[\s\S]*?<\/tr>";
const TABLE_DATA_PATTERN: &str = r"<td>[\s\S]*?<\/td>";
const TD_REMOVAL_PATTERN: &str = r"<\/?td>";
const CIPP_FIELD_EXCLUSION_PATTERN: &str = r"(CIPP|Alerts|Alert)";

/// Strips useful data from table rows from string
/// Expects \r\n newline
/// Expects table columns Message,API,Tenant,Username,Severity
/// Expects one table
pub fn parse_messages_from_email_alert_body_v1(
    body: String,
    domain_exclusions: Vec<String>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let mut results: Vec<String> = Vec::new();
    let mut error_messages: Vec<String> = Vec::new();
    let body = body.replace(r"\r\n", "");

    let tr_regex = Regex::new(TABLE_ROW_PATTERN).unwrap();
    let td_regex = Regex::new(TABLE_DATA_PATTERN).unwrap();
    let td_remove_regex = Regex::new(TD_REMOVAL_PATTERN).unwrap();
    let cipp_field_exclusions_regex = Regex::new(CIPP_FIELD_EXCLUSION_PATTERN).unwrap();
    let domain_exclusions_regex = match Regex::new(&format!(
        "({})",
        domain_exclusions
            .iter()
            .map(|exclusion| regex::escape(exclusion))
            .collect::<Vec<String>>()
            .join("|")
    )) {
        Ok(regex) => regex,
        Err(err) => {
            return Err(format!(
                "Invalid input for generating dynamic regex pattern, {}",
                err
            )
            .into())
        }
    };

    let rows: Vec<&str> = tr_regex
        .find_iter(&body)
        .map(|mat| mat.as_str())
        .collect::<Vec<&str>>()[1..]
        .to_vec();
    rows.into_iter().for_each(|row| {
        if domain_exclusions.len() == 0 || !domain_exclusions_regex.is_match(row) {
            let mut useful_fields: Vec<String> = Vec::new();
            td_regex.find_iter(&row).map(|mat| mat.as_str()).for_each(|field| {
                let field = td_remove_regex.replace_all(field, "").to_string();
                if !cipp_field_exclusions_regex.is_match(&field) {
                    useful_fields.push(field);
                }
            });
            if useful_fields.len() != 2 {
                error_messages.push(format!("Something is wrong with data extracted from row, expected exactly 2 useful fields, skipping this one in output: {:?}", useful_fields));
            } else {
                results.push(format!("{} ({})", useful_fields[0], useful_fields[1]))
            }
        }
    });
    println!("{:?}", results);
    Ok((results, error_messages))
}

#[cfg(test)]
mod tests {
    use super::*;
    const CIPP_EMAIL_BODY_TEST_DATA: &str = r#"<html>\r\n<head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=us-ascii\">\r\n</head>\r\n<body>\r\nYou've setup your alert policies to be alerted whenever specific events happen. We've found some of these events in the log:<br>\r\n<br>\r\n<style>table.blueTable{border:1px solid #1C6EA4;background-color:#EEE;width:100%;text-align:left;border-collapse:collapse}table.blueTable td,table.blueTable th{border:1px solid #AAA;padding:3px 2px}table.blueTable tbody td{font-size:13px}table.blueTable tr:nth-child(even){background:#D0E4F5}table.blueTable thead{background:#1C6EA4;background:-moz-linear-gradient(top,#5592bb 0,#327cad 66%,#1C6EA4 100%);background:-webkit-linear-gradient(top,#5592bb 0,#327cad 66%,#1C6EA4 100%);background:linear-gradient(to bottom,#5592bb 0,#327cad 66%,#1C6EA4 100%);border-bottom:2px solid #444}table.blueTable thead th{font-size:15px;font-weight:700;color:#FFF;border-left:2px solid #D0E4F5}table.blueTable thead th:first-child{border-left:none}table.blueTable tfoot{font-size:14px;font-weight:700;color:#FFF;background:#D0E4F5;background:-moz-linear-gradient(top,#dcebf7 0,#d4e6f6 66%,#D0E4F5 100%);background:-webkit-linear-gradient(top,#dcebf7 0,#d4e6f6 66%,#D0E4F5 100%);background:linear-gradient(to bottom,#dcebf7 0,#d4e6f6 66%,#D0E4F5 100%);border-top:2px solid #444}table.blueTable tfoot td{font-size:14px}table.blueTable tfoot .links{text-align:right}table.blueTable tfoot .links a{display:inline-block;background:#1C6EA4;color:#FFF;padding:2px 8px;border-radius:5px}</style>\r\n<table class=\"blueTable\">\r\n<colgroup><col><col><col><col><col></colgroup>\r\n<tbody>\r\n<tr>\r\n<th>Message</th>\r\n<th>API</th>\r\n<th>Tenant</th>\r\n<th>Username</th>\r\n<th>Severity</th>\r\n</tr>\r\n<tr>\r\n<td>MICROSOFT 365 BUSINESS STANDARD will expire in 141 days</td>\r\n<td>Alerts</td>\r\n<td>dummydomaina.com.au</td>\r\n<td>CIPP</td>\r\n<td>Alert</td>\r\n</tr>\r\n<tr>\r\n<td>EXCHANGE ONLINE (PLAN 2) will expire in 358 days</td>\r\n<td>Alerts</td>\r\n<td>dummydomainb.com.au</td>\r\n<td>CIPP</td>\r\n<td>Alert</td>\r\n</tr>\r\n<tr>\r\n<td>Microsoft Defender for Office 365 (Plan 1) will expire in 307 days</td>\r\n<td>Alerts</td>\r\n<td>dummydomainc.com.au</td>\r\n<td>CIPP</td>\r\n<td>Alert</td>\r\n</tr>\r\n</tbody>\r\n</table>\r\n</body>\r\n</html>\r\n;"#;
    #[test]
    fn test_parse_messages_from_email_alert_body_v1() {
        let output = parse_messages_from_email_alert_body_v1(
            CIPP_EMAIL_BODY_TEST_DATA.to_string(),
            vec!["dummydomainc.com.au".to_string()],
        )
        .unwrap();
        assert_eq!(output, (vec!["MICROSOFT 365 BUSINESS STANDARD will expire in 141 days: (dummydomaina.com.au)".to_string(), "EXCHANGE ONLINE (PLAN 2) will expire in 358 days: (dummydomainb.com.au)".to_string()], vec![]))
    }
}
