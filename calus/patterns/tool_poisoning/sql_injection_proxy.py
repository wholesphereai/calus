"""tool-poisoning: sql-injection-proxy  (2 patterns)"""

PATTERNS = [
    ('(?:/litellm|/v1/team|/v1/user|/v1/model|/v1/key|/v1/admin|/team/(?:new|update|delete|info)|/user/(?:new|update|delete|info)|/key/(?:generate|update|delete|info)|/model/(?:new|update|delete|info))[\\s\\S]{0,500}(?:\'\\s*(?:OR|UNION|AND|SELECT|--|;)|"\\s*(?:OR|UNION|AND|SELECT|--|;)|%27\\s*(?:OR|UNION|AND|SELECT)|\\bOR\\s+1\\s*=\\s*1\\b|\\bUNION\\s+(?:ALL\\s+)?SELECT\\b|;\\s*DROP\\s+TABLE|;\\s*DELETE\\s+FROM|--\\s*$|/\\*.*?\\*/)', 'critical', ''),
    ('(?<![A-Za-z_])(?:team_id|user_id|key_id|model_id|customer_id|budget_id|alias_id|tag_id)\\s*[:=]\\s*["\'][\\s\\S]{0,200}(?:\'\\s*(?:OR|UNION|AND|SELECT)|"\\s*(?:OR|UNION|AND|SELECT)|\\bOR\\s+1\\s*=\\s*1\\b|\\bUNION\\s+(?:ALL\\s+)?SELECT\\b|;\\s*DROP\\s+TABLE|;\\s*DELETE\\s+FROM)', 'critical', ''),
]