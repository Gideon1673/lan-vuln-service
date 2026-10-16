WITH mapping_templates (
    rule_name,
    evaluation_type,
    condition,
    required_evidence
) AS (
    VALUES

    -- SSH: Root login
    (
        'sshd_disable_root_login',
        'CONFIG_VALUE',
        '{
            "operator": "SSH_EFFECTIVE_CONFIG",
            "parameter": "PermitRootLogin",
            "expected": "no"
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "ssh.effective_config.PermitRootLogin"
        ]'::jsonb
    ),

    -- SSH: Empty passwords
    (
        'sshd_disable_empty_passwords',
        'CONFIG_VALUE',
        '{
            "operator": "SSH_EFFECTIVE_CONFIG",
            "parameter": "PermitEmptyPasswords",
            "expected": "no"
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "ssh.effective_config.PermitEmptyPasswords"
        ]'::jsonb
    ),

    -- SSH service enabled
    (
        'service_sshd_enabled',
        'SERVICE_STATE',
        '{
            "operator": "SERVICE_ENABLED",
            "service": "sshd",
            "expected": true
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.services[].name",
            "system.services[].enabled"
        ]'::jsonb
    ),

    -- Telnet service disabled
    (
        'service_telnet_disabled',
        'SERVICE_STATE',
        '{
            "operator": "SERVICE_ENABLED",
            "service": "telnet",
            "expected": false
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.services[].name",
            "system.services[].enabled"
        ]'::jsonb
    ),

    -- Telnet server package removed
    (
        'package_telnet-server_removed',
        'PACKAGE_STATE',
        '{
            "operator": "PACKAGE_INSTALLED",
            "package": "telnet-server",
            "expected": false
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.packages[].name"
        ]'::jsonb
    ),

    -- FTP: vsftpd
    (
        'service_vsftpd_disabled',
        'SERVICE_STATE',
        '{
            "operator": "SERVICE_ENABLED",
            "service": "vsftpd",
            "expected": false
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.services[].name",
            "system.services[].enabled"
        ]'::jsonb
    ),

    -- Samba
    (
        'service_smb_disabled',
        'SERVICE_STATE',
        '{
            "operator": "SERVICE_ENABLED",
            "service": "smb",
            "expected": false
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.services[].name",
            "system.services[].enabled"
        ]'::jsonb
    ),

    -- Apache HTTPD
    (
        'service_httpd_disabled',
        'SERVICE_STATE',
        '{
            "operator": "SERVICE_ENABLED",
            "service": "httpd",
            "expected": false
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.services[].name",
            "system.services[].enabled"
        ]'::jsonb
    ),

    -- BIND DNS
    (
        'service_named_disabled',
        'SERVICE_STATE',
        '{
            "operator": "SERVICE_ENABLED",
            "service": "named",
            "expected": false
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.services[].name",
            "system.services[].enabled"
        ]'::jsonb
    ),

    -- Avahi
    (
        'service_avahi-daemon_disabled',
        'SERVICE_STATE',
        '{
            "operator": "SERVICE_ENABLED",
            "service": "avahi-daemon",
            "expected": false
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.services[].name",
            "system.services[].enabled"
        ]'::jsonb
    ),

    -- Linux IPv4 forwarding
    (
        'sysctl_net_ipv4_ip_forward',
        'SYSCTL_VALUE',
        '{
            "operator": "SYSCTL_EQUALS",
            "key": "net.ipv4.ip_forward",
            "expected": 0
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.sysctl.net.ipv4.ip_forward"
        ]'::jsonb
    ),

    -- Linux TCP SYN cookies
    (
        'sysctl_net_ipv4_tcp_syncookies',
        'SYSCTL_VALUE',
        '{
            "operator": "SYSCTL_EQUALS",
            "key": "net.ipv4.tcp_syncookies",
            "expected": 1
        }'::jsonb,
        '[
            "host.ip",
            "host.os",
            "system.sysctl.net.ipv4.tcp_syncookies"
        ]'::jsonb
    )
)

INSERT INTO vuln_misconfig_rule_mapping (
    source_id,
    source_file,
    content_sha256,
    mapping_version,
    evaluation_type,
    target,
    applicability,
    condition,
    required_evidence,
    verification_status,
    enabled,
    review_note
)
SELECT
    r.source_id,
    r.source_file,
    r.content_sha256,
    '1.0',
    m.evaluation_type,

    '{"type": "HOST"}'::jsonb,

    '{
        "os_families": ["linux"],
        "verification": "PENDING"
    }'::jsonb,

    m.condition,
    m.required_evidence,

    'DRAFT',
    FALSE,

    'Candidate mapping. Verify source check, platform, '
    || 'service/package naming and Discovery evidence.'

FROM mapping_templates m

JOIN vuln_misconfig_rule r
    ON r.external_rule_id = m.rule_name

JOIN vuln_misconfig_source s
    ON s.id = r.source_id

WHERE s.source_key = 'COMPLIANCE_AS_CODE'
  AND r.source_revision = s.last_revision
  AND r.deprecated = FALSE

ON CONFLICT (
    source_id,
    source_file,
    content_sha256,
    mapping_version
)
DO NOTHING;
