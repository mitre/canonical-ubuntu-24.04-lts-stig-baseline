control 'SV-270831' do
  title 'Ubuntu 24.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', "Verify that the Advanced Intrusion Detection Environment (AIDE) is configured to use cryptographic mechanisms to protect the integrity of the audit tools.

First, verify that the audit tools are configured within AIDE's sub-configuration directory with the following command:
$ find /etc/aide/aide.conf /etc/aide/aide.conf.d/ -type f -exec grep -H -E '^(|/usr)/sbin/au(dit(ctl|d)|search|report|rules|trace)[[:space:]]' {} +

If any of the six core audit tools (for both /usr/sbin/ and /sbin/ paths) do not return from the command, or if they are not configured with the exact rule p+i+n+u+g+s+b+acl+xattrs+sha512, this is a finding.
/etc/aide/aide.conf.d/90-stig_audit_tools:/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/aide/aide.conf.d/90-stig_audit_tools:/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512"
  desc 'fix', %q(Configure AIDE to protect the integrity of the audit tools by performing the following steps:

Create a dedicated configuration file inside AIDE's sub-configuration directory:
$ sudo nano /etc/aide/aide.conf.d/90-stig_audit_tools

Add configuration rules:

# Modern Canonical Paths
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

# Legacy Paths
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

If the legacy "/sbin/" paths are defined inside the main "/etc/aide/aide.conf" file, edit "/etc/aide/aide.conf" and comment those lines out using a "#" to prevent duplicate definition conflicts.

Validate the modified AIDE configuration to ensure no syntax warnings or errors are present:
$ sudo aide -c /etc/aide/aide.conf --config-check

This command should return no output.

Initialize the updated baseline database (this may take a few minutes):
$ sudo aideinit

Copy the newly generated database into the production directory:
$ sudo cp -p /var/lib/aide/aide.db.new /var/lib/aide/aide.db)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag gid: 'V-270831'
  tag rid: 'SV-270831r1261485_rule'
  tag stig_id: 'UBTU-24-909890'
  tag fix_id: 'F-74765r1261484_fix'
  tag cci: ['CCI-001496', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 (3)', 'AU-9 a', 'AU-9']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  # V1R7 requires selection lines for both the legacy /sbin and canonical /usr/sbin paths
  audit_tools = input('audit_tools').flat_map { |tool| [tool, tool.sub(%r{^/sbin/}, '/usr/sbin/')] }.uniq
  audit_rule_suffix = 'p+i+n+u+g+s+b+acl+xattrs+sha512'
  file_integrity_tool = input('file_integrity_tool')

  if file_integrity_tool == 'aide'
    describe file('/etc/aide/aide.conf') do
      it { should exist }
    end

    aide_files = ['/etc/aide/aide.conf'] + command("find /etc/aide/aide.conf.d -type f -printf '%p\\n' 2>/dev/null").stdout.split("\n").reject(&:empty?)
    selection_lines = Hash.new { |h, k| h[k] = [] }
    aide_files.each do |f|
      file(f).content.to_s.each_line do |line|
        match = line.match(%r{^\s*(/\S+)\s+(\S+)\s*$})
        selection_lines[match[1]] << match[2] if match
      end
    end

    describe 'AIDE audit tools selection lines' do
      it 'must include exact lines for all audit tools' do
        missing = audit_tools.reject { |tool| selection_lines[tool].any? && selection_lines[tool].all?(audit_rule_suffix) }
        expect(missing).to be_empty, "Missing or incorrect lines in /etc/aide/aide.conf or /etc/aide/aide.conf.d/ for: #{missing.join(', ')}"
      end
    end
  else
    describe 'The system is not utilizing Advanced Intrusion Detection Environment (AIDE)' do
      skip 'The system is not utilizing Advanced Intrusion Detection Environment (AIDE), manual review is required.'
    end
  end
end
