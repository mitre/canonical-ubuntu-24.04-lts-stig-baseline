control 'SV-270680' do
  title 'Ubuntu 24.04 LTS must automatically terminate a user session after inactivity timeouts have expired.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance."
  desc 'check', 'Verify Ubuntu 24.04 LTS automatically terminates a user session after inactivity timeouts have expired with the following command:

$ sudo grep -E "\\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*
/etc/profile.d/99-terminal_tmout.sh:TMOUT=600

If "TMOUT" is not set, or if the value is "0" or is commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to automatically terminate a user session after inactivity timeouts have expired or at shutdown.

Create the file "/etc/profile.d/99-terminal_tmout.sh" file if it does not exist.

Modify or append the following line in the "/etc/profile.d/99-terminal_tmout.sh " file:

TMOUT=600

This will set a timeout value of 10 minutes for all future sessions.

To set the timeout for the current sessions, execute the following command over the terminal session:

$ export TMOUT=600'
  impact 0.5
  tag check_id: 'C-74713r1066527_chk'
  tag severity: 'medium'
  tag gid: 'V-270680'
  tag rid: 'SV-270680r1066529_rule'
  tag stig_id: 'UBTU-24-200060'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-74614r1066528_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  timeout_setting = command("grep -E '\\bTMOUT=[0-9]+' /etc/bash.bashrc /etc/profile.d/*.sh 2>/dev/null | tail -n1").stdout.strip.match(/TMOUT=(?<timeout>\d+)/)
  expected_timeout = input('system_activity_timeout')

  describe 'Shell inactivity timeout (TMOUT)' do
    it 'should be set' do
      expect(timeout_setting).to_not be_nil, 'TMOUT not set in /etc/bash.bashrc or /etc/profile.d/*.sh'
    end
    unless timeout_setting.nil?
      it "should lock the session after #{expected_timeout} seconds" do
        expect(timeout_setting['timeout'].to_i).to cmp <= expected_timeout
      end
    end
  end
end
