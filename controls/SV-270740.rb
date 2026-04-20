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

  audit_file = '/var/log/sudo.log'

  if auditd.lines.nil? || auditd.lines.empty?
    describe 'Audit rules' do
      it 'should have audit rules loaded and auditd configured' do
        expect(auditd.lines).not_to be_nil, 'auditd is not configured or not available'
        expect(auditd.lines).not_to be_empty, 'auditd is configured but no audit rules are loaded'
      end
    end
  else
    describe auditd.file(audit_file) do
      it { should exist }
      its('action') { should_not include 'never' }
      its('permissions.flatten') { should include('w', 'a') }
    end
  end
end
