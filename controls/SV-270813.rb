control 'SV-270813' do
  title 'Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to use modprobe command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify if Ubuntu 24.04 LTS is configured to audit the execution of the module management program "modprobe" with the following command:

$ sudo auditctl -l | grep '/sbin/modprobe'
-w /sbin/modprobe -p x -k modules

If the command does not return a line, or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS to audit the execution of the module management program "modprobe".

Add or update the following rule in the "/etc/audit/rules.d/stig.rules" file:

-w /sbin/modprobe -p x -k modules

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74846r1066926_chk'
  tag severity: 'medium'
  tag gid: 'V-270813'
  tag rid: 'SV-270813r1066928_rule'
  tag stig_id: 'UBTU-24-900730'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-74747r1066927_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_command = '/sbin/modprobe'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('x')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
