control 'SV-270740' do
  title 'Ubuntu 24.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions, and other system-level access.'
  desc 'If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.'
  desc 'check', 'Verify Ubuntu 24.04 LTS audits activities performed during nonlocal maintenance and diagnostic sessions with the following command:

$ sudo auditctl -l | grep sudo.log
-w /var/log/sudo.log -p wa -k maintenance

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to audit activities performed during nonlocal maintenance and diagnostic sessions.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-w /var/log/sudo.log -p wa -k maintenance

To reload the rules file, issue the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74773r1066707_chk'
  tag severity: 'medium'
  tag gid: 'V-270740'
  tag rid: 'SV-270740r1066709_rule'
  tag stig_id: 'UBTU-24-500010'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-74674r1066708_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002884', 'CCI-004188']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)', 'MA-3 (5)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_command = '/var/log/sudo.log'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
