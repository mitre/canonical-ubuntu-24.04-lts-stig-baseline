control 'SV-274870' do
  title 'Ubuntu 24.04 LTS must audit any script or executable called by cron as root or by any privileged user.'
  desc 'Any script or executable called by cron as root or by any privileged user must be owned by that user, must have the permissions 755 or more restrictive, and should have no extended rights that allow any nonprivileged user to modify the script or executable.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is configured to audit the execution of any system call made by cron as root or as any privileged user.

$ sudo auditctl -l | grep /etc/cron.d
-w /etc/cron.d -p wa -k cronjobs

$ sudo auditctl -l | grep /var/spool/cron
-w /var/spool/cron -p wa -k cronjobs

If either of these commands does not return the expected output, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to audit the execution of any system call made by cron as root or as any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":
-w /etc/cron.d/ -p wa -k cronjobs
-w /var/spool/cron/ -p wa -k cronjobs

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78971r1155225_chk'
  tag severity: 'medium'
  tag gid: 'V-274870'
  tag rid: 'SV-274870r1155243_rule'
  tag stig_id: 'UBTU-24-200270'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-78876r1155226_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audited_paths = %w[/etc/cron.d /var/spool/cron]

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audited_paths.each do |audit_path|
    describe "Audit rules for #{audit_path}" do
      it "#{audit_path} is audited properly" do
        audit_rule = auditd.file(audit_path)
        expect(audit_rule).to exist
        expect(audit_rule.permissions.flatten).to include('w', 'a')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_path])
      end
    end
  end
end
