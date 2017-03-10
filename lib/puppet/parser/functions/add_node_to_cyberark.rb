require 'openssl'
require 'uri'
require 'net/http'
require 'json'
require 'yaml'
module Puppet::Parser::Functions
  newfunction(:add_node_to_cyberark) do |args|
    serveraddress = lookupvar('fqdn')
    logonusername = call_function('hiera',['cyberark_functions::logonusername'])
    logonpassword = call_function('hiera',['cyberark_functions::logonpassword'])
    safe = call_function('hiera', ['cyberark_functions::safe'])
    devicetype = call_function('hiera',['cyberark_functions::devicetype'])
    platformid = call_function('hiera',['cyberark_functions::platformid'])
    initialpw = call_function('hiera',['cyberark_functions::initialpw'])
    serverusername = call_function('hiera',['cyberark_functions::serverusername'])
    cyberarkserver = call_function('hiera',['cyberark_functions::cyberarkserver'])
    logonurl = URI.parse "https://#{cyberarkserver}/PasswordVault/WebServices/auth/cyberark/CyberArkAuthenticationService.svc/logon"
    existurl = URI.parse "https://#{cyberarkserver}/PasswordVault/WebServices/PIMServices.svc/Account/#{serveraddress}%7C#{serverusername}/PrivilegedCommands"
    accounturl = URI.parse "https://#{cyberarkserver}/PasswordVault/WebServices/PIMServices.svc/Account"
    logouturl = URI.parse "https://#{cyberarkserver}/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff"

    ### Well we need to logon
    http = Net::HTTP.new(logonurl.host, logonurl.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Post.new(logonurl.request_uri)
    request['content-type'] = 'application/json'
    request['cache-control'] = 'no-cache'
    request.body = "{\"username\":\"#{logonusername}\",\"password\":\"#{logonpassword}\"}"
    response = http.request(request)
    parseresponse = JSON.parse(response.body)
    ### Finally we have the logon Token
    token = parseresponse['CyberArkLogonResult']

    ### Check and see if the account exists
    http = Net::HTTP.new(existurl.host, existurl.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Get.new(existurl.request_uri)
    request['content-type'] = 'application/json'
    request['cache-control'] = 'no-cache'
    request['authorization'] = token
    request.body = ""

    response = http.request(request)
    existscode = response.code
    puts existscode

    unless existscode == '200'
      http = Net::HTTP.new(accounturl.host, accounturl.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE

      request = Net::HTTP::Post.new(accounturl.request_uri)
      request['content-type'] = 'application/json'
      request['authorization'] = token
      request['cache-control'] = 'no-cache'
      request.body = "{\n    \"account\":{\n    \"safe\":\"#{safe}\",\n    \"deviceType\":\"#{devicetype}\",\n    \"platformID\":\"#{platformid}\",\n    \"address\":\"#{serveraddress}\",\n    \"password\":\"#{initialpw}\",\n    \"username\":\"#{serverusername}\"\n    }\n}"

      response = http.request(request)
      puts response.body
    end
    ### Well time to logout
    http = Net::HTTP.new(logouturl.host, logouturl.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = Net::HTTP::Post.new(logouturl.request_uri)
    request['cache-control'] = 'no-cache'
    request['authorization'] = token
    request.body = ""
    response = http.request(request)
    puts response.read_body
  end
end
