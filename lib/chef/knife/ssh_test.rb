#! /Users/u116087/.rvm/rubies/ruby-2.0.0-p594/bin/ruby
require 'net/ssh'
require 'logger'
require 'pp'

def remote_command(command)
        begin
        Net::SSH.start('78.137.97.222', 'root',
               :password =>'Plkn$4001') do |session|
          pp #{command}
          puts #{command}
          cmd = command
            session.process.popen3(cmd) do |stdin, stdout, stderr|
              puts stdout.read
            end
        end
        rescue Timeout::Error, Errno::ECONNREFUSED
          puts "Unable to connect to "
        end
end

def ssh_command(comm,user,password)
        begin
          ssh = Net::SSH.start('78.137.97.222', user, 
            :password => password, :paranoid => false)
          res = ssh.exec!(comm)
          ssh.close
          puts res
        rescue Timeout::Error, Errno::ECONNREFUSED
          puts "Unable to connect to #{@server.public_ips.first} "
        end
end

ssh_command('cd /etc; ls -alt', '78.137.97.222', 'root', '')