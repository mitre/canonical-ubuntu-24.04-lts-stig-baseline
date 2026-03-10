control 'SV-270819' do
  title 'Ubuntu 24.04 LTS must alert the system administrator (SA) and information system security officer (ISSO) (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

    This requirement applies to each audit data storage repository (i.e.,
distinct information system component where audit records are stored), the
centralized audit storage capacity of organizations (i.e., all audit data
storage repositories combined), or both.'
  desc 'check', %q(Verify that the SA and ISSO (at a minimum) are notified in the event of an audit processing failure with the following command: 
 
$ sudo grep '^action_mail_acct' /etc/audit/auditd.conf
action_mail_acct = <administrator_account> 
 
If the value of the "action_mail_acct" keyword is not set to an account for security personnel, the returned line is commented out, or the keyword is missing, this is a finding.)
  desc 'fix', 'Configure "auditd" service to notify the SA and ISSO in the event of an audit processing failure.  
 
Edit the following line in "/etc/audit/auditd.conf" to ensure administrators are notified via email for those situations: 
 
action_mail_acct = <administrator_account> 
 
Note: Change "administrator_account" to an account for security personnel. 
 
Restart the "auditd" service so the changes take effect: 
 
$ sudo systemctl restart auditd.service'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag gid: 'V-270819'
  tag rid: 'SV-270819r1068390_rule'
  tag stig_id: 'UBTU-24-900980'
  tag fix_id: 'F-74753r1066945_fix'
  tag cci: ['CCI-000139', 'CCI-001855']
  tag nist: ['AU-5 a', 'AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe auditd_conf do
    its('action_mail_acct') { should cmp 'root' }
  end
end
