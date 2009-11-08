module Nessus
  
  # Host
  attr_reader :host
  # Port
  attr_reader :port
  # User
  attr_reader :user
  # Password
  attr_reader :password
  # Targets File
  attr_reader :targets_file
  # Result File
  attr_reader :result_file
  
  class Scan
    
    # nessus -q [-pPS] <host> <port> <user> <pass> <targets-file> <result-file>
    def initialize(host,port,user,password,targets_file,result_file,options={})
      
    end
    
  end
  
end