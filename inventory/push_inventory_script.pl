#!/usr/bin/perl -w
##################################################################
#                     Push Inventory Script                     
# Author: Jesse Morgan                                           
# Purpose: Scan a given subnet, and add entries to LDAP          
# Logic:
#   Scan the given network, create a master list of IP addresses
#   search ldap for [linux,solaris] hosts
#       copy fresh inventory script to target machines
#
#   For each IP address running ssh
#       Attempt to identify
#       copy inventory script
##################################################################

#TODO: document "undeployed" ip addresses more clearly
#TODO: use logfiles
use lib '../lib';
use strict;
use warnings;
use Carp;
use Config::IniFiles;
use Data::Dumper;
use MorgInvSys;
use Net::IP::Match::Regexp qw( create_iprange_regexp match_ip );
use Net::LDAP;
use Net::SNMP;
use Switch;
use Thread::Pool::Simple;

my $mainconfig = Config::IniFiles->new( -file => "../configs/config.ini" ) or croak "Could not open your config!";

my @rangelist = @ARGV;

if ( scalar(@rangelist) == 0 ) {
    @rangelist=get_default_range($mainconfig,'scannable network');
} ## end if ( scalar(@rangelist...))


####################################################################
# Take list of ranges provided on the CLI and 
# generate an array of responsive IP addresses                                          #
####################################################################
my @ips = &scan_ranges( $mainconfig, @rangelist );

###########################################
# Loop through the remaining IP addresses #
# and scan the system, generating an LDIF #
###########################################
scan_ips($mainconfig,@ips);

exit;

########################################################################
########################################################################
########################################################################
########################################################################


##################################################
##
## Given a list of IPs, loop through each on to
## scan and maybe upload an inventory script.
##
##################################################
sub scan_ips{
    my ($config,@ips)=@_;
    my $mainPool = Thread::Pool::Simple->new(
        load => $config->val( 'Threading', 'load' ),
        min  => $config->val( 'Threading', 'min' ),
        max  => $config->val( 'Threading', 'max' ),
        do   => [ \&scan_and_upload ],
    );

    # Loop through to start the process
    my @mainThreadIDs;
    foreach my $ip (@ips) {
        push @mainThreadIDs, $mainPool->add( $config, $ip );    # call in list context
    }

    # wait for threads to finish
    $mainPool->join();          

    #loop through to reap the results
    foreach my $id (@mainThreadIDs) {
        $mainPool->remove($id);
    }
}

##################################################
##
## Check to see if the ip is an ilo; if not check
## if ssh is set up, deploy the file.
##
##################################################
sub scan_and_upload {
    my ( $config, $ip ) = @_;

    # Make sure it's not an ilo, that it has SSH and a valid key, then copy the file.
    if ( is_an_ilo($config,$ip) ) {
        return "# $ip appears to be an iLO; do nothing.\n";
    } else {
        if ( &has_ssh_key_setup( $config, $ip ) ) {
            if ( &deploy_script( $config, $ip ) == 0 ) {
                return "# $ip SSH key configured. scp file complete ($?).\n";
            } else {
                return "# $ip SSH key configured. scp failed for unknown reason($?).\n";
            }
        } else {
            return "# $ip No ssh key, can't push config\n";
        }
    }
}

##################################################
##
## Check to see if an IP address has is an ILO
## using curl.
##
##################################################
sub is_an_ilo {
    my ( $config, $ip ) = @_;
    # Note, no credentials are needed for this iLO page
    my ( $stdin, $stdout, $err );
    my $pid = open3( $stdin, $stdout, $err, "curl", "--proxy", '""', "--fail", "--silent", "--max-time", "3", "http://$ip/xmldata?item=All");
    #my $pid = open3( $stdin, $stdout, $err, "curl", "--max-time", "10","--connect-timeout","10", "-fs", "--insecure", "https://$ip/xmldata?item=All" );
    waitpid $pid, 0 ;
    my @output = <$stdout>;
    my $curloutput = join " ", @output;
    if ( $curloutput =~ /<RIMP>/xms ) {
        return 1;
    } else { 
        return 0;
    }
}


##################################################
##
## Target ip has SSH and a key set up; determine 
## which script needs to be deployed and deploy it.
##
##################################################
sub deploy_script {
    #FIXME This method is garbage. Rewrite!
    # SSH appears to be up and functional; we need to figure out what it is, and push the right inventory script.
    my ( $config, $ip ) = @_;

    my @options = $config->val( 'Network', 'ssh_option' );

    # This command should be a good distinguisher
    my @output = execute_command( $config, $ip, "cat /etc/issue 2>/dev/null && uname -a " );

    # Bash and perl disagree on the value of success, however VMS and perl DO agree
    # hence the negations of the f5, linux and solaris scripts
    my $command
        = "@output" =~ /BIG-IP/xmsi             ? "/usr/bin/scp @options ./f5_inventory.sh      $ip:/config/f5_inventory.sh    &>/dev/null"
        : "@output" =~ /linux/xmsi              ? "/usr/bin/scp @options ./linux_inventory.sh   $ip:/tmp/linux_inventory.sh    &>/dev/null"
        : "@output" =~ /sun/xmsi                ? "/usr/bin/scp @options ./solaris_inventory.sh $ip:/tmp/solaris_inventory.sh  &>/dev/null"
        : "@output" =~ /unrecognized.*verb/xmsi ? "/usr/bin/scp @options ./vms_inventory.com    $ip:vms_inventory.com          &>/dev/null"
        : "false";
    #FIXME don't use system calls dumbass.
    system($command);
    my $exitcode = $?;

    if (   ( "@output" =~ /unrecognized.*verb/xmsi and $exitcode == 256 )
        or ( "@output" !~ /unrecognized.*verb/xmsi and $exitcode == 0 ) )
    {
        return 0;
    } else {
        return $exitcode;
    }
}


##################################################
##
## Determine if SSH keys have been set up.
##
##################################################
sub has_ssh_key_setup {
    #FIXME don't use system calls dumbass.
    my ( $config, $ip ) = @_;
    my @options = $config->val( 'Network', 'ssh_option' );
    system("ssh -q @options $ip true");
    if ( $? == 65280 ) {
        print "$ip failed ssh key test\n";
        return 0;
    } else {
        return 1;
    }
}


##################################################
##
## Take a given set of ranges, and cycle through 
## each and do an fping on each in parallel.
##
##################################################
sub scan_ranges {
    my ( $config, @ranges ) = @_;
    my $pool = Thread::Pool::Simple->new(
        load => $config->val( 'Threading', 'load' ),
        min  => $config->val( 'Threading', 'min' ),
        max  => $config->val( 'Threading', 'max' ),
        do   => [ \&scan_ssh ],
    );
    print "# loop through all ranges\n";
    my @threadIDs;
    foreach my $range (@ranges) {
        push @threadIDs, $pool->add($range);    # call in list context
    }
    $pool->join();                              # wait till all jobs are done
    print "# scanning threads joined.\n";

    my @ips;
    foreach my $id (@threadIDs) {
        @ips = ( @ips, $pool->remove($id) );
    }
    print "# We have " . scalar(@ips) . " IPs where we will attempt to deploy inventory scripts.\n";
    return @ips;

} ## end sub scan_ranges

##################################################
##
## nmap an entire subnet and return an array of 
## active IP addresses
##
##################################################
sub scan_ssh {
    my ($subnet) = @_;
    print("Scanning $subnet\n");

    my ( $stdin, $stdout, $err );
    my $pid = open3( $stdin, $stdout, $err, "nmap", "-p", "22", "-oG", "-", $subnet );
    waitpid $pid, 0 ;
    my @results = <$stdout>;
    @results = grep { /Ports:.*22\/open\//xms } @results;
    @results = map { ( split( ' ', $_ ) )[1] } @results;

    return @results;
} ## end sub scan_ssh
