control 'SV-274868' do
  title 'Ubuntu 24.04 LTS must require users to provide a password for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical that the user reauthenticate.'
  desc 'check', %q(Verify that "/etc/sudoers" has no occurrences of "NOPASSWD" with the following command:

$ sudo egrep -iR 'NOPASSWD' /etc/sudoers /etc/sudoers.d/

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the information system security officer (ISSO) as an organizationally defined administrative group using multifactor authentication (MFA), this is a finding.)
  desc 'fix', %q(Configure the operating system to not allow users to execute privileged actions without authenticating with a password.

Remove any occurrence of "NOPASSWD" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.

$ sudo find /etc/sudoers /etc/sudoers.d -type f -exec sed -i '/NOPASSWD/ s/^/# /g' {} \;)
  impact 0.5
  tag check_id: 'C-78969r1101743_chk'
  tag severity: 'medium'
  tag gid: 'V-274868'
  tag rid: 'SV-274868r1107313_rule'
  tag stig_id: 'UBTU-24-300020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-78874r1101744_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-004895', 'CCI-000366']
  tag nist: ['IA-11', 'SC-11 b', 'CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  sudo = sudoers(input('sudoers_config_files'))
  approved_groups = Array(input('passwordless_admins'))

  # Identify NOPASSWD rules
  nopass = sudo.rules.where { !tags.nil? && tags.include?('NOPASSWD:') }

  # Allow only NOPASSWD rules for ISSO-approved admin groups (group entries begin with '%')
  unauthorized = nopass.entries.reject do |r|
    userspec = r[:users]
    next false if userspec.nil?

    if userspec.start_with?('%')
      grp = userspec.sub(/^%/, '')
      approved_groups.include?(grp)
    else
      false
    end
  end

  unauthorized_details = unauthorized.map { |r| "#{r[:users]} #{r[:hosts]}= #{r[:commands]}" }.join('; ')

  describe 'Disallowed NOPASSWD entries in sudoers' do
    subject { unauthorized }
    it 'should be empty (only ISSO-approved admin groups using MFA may be NOPASSWD)' do
      expect(subject).to be_empty, "Unauthorized NOPASSWD entries: #{unauthorized_details}"
    end
  end
end
