#!/usr/bin/perl -w

####################################################################
#                    IP Usage Audit Report                         #
# Author: Jesse Morgan                                             #
# Purpose: Scan a range of IP addresses and report redundant or    #
# duplicate reverse IP addresses, and make sure DNS reverses have  #
# corresponding forwards.                                          #
####################################################################

use lib '../';
use strict;
use warnings;
use Carp;
use Config::IniFiles;
use Data::Dumper;
use Getopt::Long qw( :config auto_help );
use IPC::Open3;
use MorgInvSys;
use Net::Netmask;
use Thread::Pool::Simple;
use Time::Duration;

my $starttime = time();

# First step is to read in our main configuration file.
my $mainconfig = Config::IniFiles->new( -file => "../configs/config.ini" ) or croak "Could not open your config!";

# Next we instantiate all of the variables associated with GetOpts, then call GetOpts.
my @rangelist = ();
GetOptions( 'range=s@{,}' => \@rangelist, );

# If @rangelist is empty, grab the default ranges from our config file
if ( scalar(@rangelist) == 0 ) {
    @rangelist = get_default_range($mainconfig, 'scannable network');
}

my @content;
push @content, generate_header();
push @content, generate_content( $mainconfig, @rangelist );
push @content, generate_footer($starttime);

write_page_to_wiki($mainconfig,"Reverse DNS Entry Cleanup",@content);

exit;
#############################################
#############################################
#############################################
#############################################


##################################################
##
## Generate the page content for mismatches, 
## including hosts with multiple forwards, No DNS 
## entry or mismatching forwards and reverses.
##
##################################################
sub generate_mismatches {
    my ( $multipleforwards, $nodnsentry, $resolvemismatch ) = @_;
    my @content;
    push @content, "\n#########################################################";
    push @content, "These hosts have reverse entries where the forward doesn't match!";
    if ( scalar(@$multipleforwards) > 0 ) {
        push @content, " - These hosts have multiple forwards (" . scalar(@$multipleforwards) . " total):";
        push @content, @$multipleforwards;
    }
    if ( scalar(@$nodnsentry) > 0 ) {
        push @content, " - These hosts have no DNS entry (" . scalar(@$nodnsentry) . " total):";
        push @content, @$nodnsentry;
    }
    if ( scalar(@$resolvemismatch) > 0 ) {
        push @content,
            " - These hosts have mismatching forwards and reverses (" . scalar(@$resolvemismatch) . " total):";
        push @content, @$resolvemismatch;
    }
    return @content;
} ## end sub generate_mismatches


##################################################
##
## Generate the content for two ips that reverse to the
## same hostname and multiple reverses for a single IP
##
##################################################
sub generate_reverse_collisions {
    my ( $host_ips, $ip_hosts ) = @_;
    my @content;
    push @content, "\n#########################################################";
    push @content, "These IP addresses reverse to the same hostnames!";
    foreach my $hostname ( keys %$host_ips ) {
        if ( scalar( @{ $host_ips->{$hostname} } ) > 1 ) {
            push @content,
                  join( ', ', @{ $host_ips->{$hostname} } )
                . " all resolve as $hostname (which resolves as "
                . join( ', ', forward_lookup($hostname) ) . ")";

        } ## end if ( scalar( @{ $host_ips...}))
    } ## end foreach my $hostname ( keys...)
    push @content, "\n#########################################################";
    push @content,
        "These hosts have multiple reverse entries for a single IP (" . scalar( keys %$ip_hosts ) . " total):";

    foreach my $ip ( keys %$ip_hosts ) {
        push @content, "$ip = " . join( ' ', @{ $ip_hosts->{$ip} } );
    }
    return @content;
} ## end sub generate_reverse_collisions


##################################################
##
## Generate content for Active IPs with no reverses
##
##################################################
sub generate_no_reverses {
    my ($no_reverse) = @_;
    my @content;
    push @content, "\n#########################################################";
    push @content, "These IPs are active, but have no reverse ( " . ( scalar(@$no_reverse) || 0 ) . " total):";
    foreach my $host (@$no_reverse) {
        my $hostname = $host->{'hostname'} || '';
        push @content, $host->{'ip'} . ' is active but has no reverse ' . $hostname . '!';
    }

    return @content;
} ## end sub generate_no_reverses


##################################################
##
## This is the main content generation routine; 
## it massages the ip_dns_records into the 
## correct forms, then feed them to the generation 
## subroutines with the output being the finished 
## content.
##
##################################################
sub generate_content {
    my ( $config, @rangelist ) = @_;

    # use our rangelist to create an array of IPs that we can loop through
    my @iplist = create_ip_list(@rangelist);
    print "Scanning " . scalar(@iplist) . " ip addresses\n";

    # For each IP, get a list of it's reverses.
    my $ip_records = scan_reverse_lookups( $mainconfig, \@iplist );
    print "\nReverse records scanned.\n";
    # Most of the heavy lifting is done at this point, time to print it
    ################################################################################

    # Create the following lists
    # * ips with multiple hostname reverses
    # * hostnames with multiple reverses pointing to it
    # * alive but has no reverses
    my ( $ip_w_host, $host_w_ip, $alive_no_reverse ) = interpret_reverses($ip_records);

    # Create another thread pool and loop through our ip_w_host and check reverses.
    my ( $multipleforwards, $nodnsentry, $resolvemismatch ) = scan_reverse_matches( $config, $ip_w_host );

    my @content;
    push @content, "{code}";
    push @content, generate_mismatches( $multipleforwards, $nodnsentry, $resolvemismatch );
    push @content, generate_reverse_collisions( $host_w_ip, $ip_w_host );
    push @content, generate_no_reverses($alive_no_reverse);
    push @content, "{code}";

    return @content;
} ## end sub generate_content


##################################################
##
## The guts of our check uses dig +short to do 
## reverse lookups, returning one hostname per 
## line. From that, we build our datastructure 
## that gets passed back.
##
##################################################
sub reverse_lookup {
    my ( $config, $ip ) = @_;
    my $dns_info;
    $dns_info->{'ip'} = $ip;

    my ( $stdin, $stdout, $err );
    my $pid = open3( $stdin, $stdout, $err, 'dig', '+short', '-x', $ip );
    waitpid $pid, 0;
    my @names = <$stdout>;
    chomp @names;
    $dns_info->{'names'} = [ sort @names ];

    $pid = open3( $stdin, $stdout, $err, '/usr/sbin/fping', $ip );
    waitpid $pid, 0;
    $dns_info->{'alive'} = grep { /alive/ } <$stdout>;
    chomp $dns_info->{'alive'};

    # we print the dot so we can see the app is running- it shows our progress.
    print ".";

    if ( scalar(@names) == 0 and scalar $dns_info->{'alive'} == 1 ) {

        # If you're not using LDAP to track inventory, you can comment this out.
        $dns_info->{'hostname'} = check_ldap_hostnames( $config, $ip );
    }
    return $dns_info;
} ## end sub reverse_lookup


##################################################
##
## Contains logic for checking LDAP for hosts 
## with an iphostnumber of $ip If you're not 
## using ldap, you can ignore this guy.
##
##################################################
sub check_ldap_hostnames {
    my ( $config, $ip ) = @_;
    my $ldap = Net::LDAP->new( $config->val( 'LDAP', 'host' ) ) or croak "$@";

    # Perform a base ldap search for $ip
    my $results = ldap_search($config, "(&" . $config->val( 'LDAP Filters', 'hosts' ) . "(iphostnumber=$ip))");

    # If that IP is found, return a string containing them.
    if ( $results->count() ) {
        my @hosts;
        foreach my $host ( $results->entries() ) {
            push @hosts, $host->get_value('cn');
        }
        return "associated in ldap with: " . join( ', ', @hosts ) . ")";
    } ## end if ( $results->count)

    # no results? return nothing.
    return;
} ## end sub check_ldap_hostnames


##################################################
##
## The guts of our check uses dig +short to do 
## reverse lookups, returning one hostname per 
## line. From that, we build our datastructure 
## that gets passed back.
##
##################################################
sub forward_lookup {
    my ($name) = @_;

    # Check your regular DNS
    my ( $stdin, $stdout, $err );
    my $pid = open3( $stdin, $stdout, $err, 'dig', '+short', $name );
    waitpid $pid, 0;
    my @internal_ips = <$stdout>;
    chomp @internal_ips;
    @internal_ips = sort @internal_ips;

    # Check google's externally visible DNS
    $pid = open3( $stdin, $stdout, $err, 'dig', '+short', $name, ' @8.8.8.8' );
    waitpid $pid, 0;
    my @external_ips = <$stdout>;
    chomp @external_ips;
    @internal_ips = sort @internal_ips;

    # Strip external entries that already exist internally (i.e. IPs match)
    my %internal_hash;
    @internal_hash{@internal_ips} = undef;
    @external_ips = grep { not exists $internal_hash{$_} } @external_ips;

    @external_ips = map { 'external: ' . $_ } @external_ips;
    @external_ips = sort @external_ips;

    my @ips = ( @internal_ips, @external_ips );
    chomp @ips;
    return @ips;
} ## end sub forward_lookup


##################################################
##
## Given an IP and a hash or hostnames and IPs, 
## determine if there are any bad reverses in the 
## forward IPs.
##
##################################################
sub check_reverse_match {
    my ( $config, $ip, $hostnames ) = @_;
    my $bad_reverses = {
        'multipleforwards' => [],
        'nodnsentry'       => [],
        'resolvemismatch'  => [],
    };

    # check the name for the $ip in $hostnames
    foreach my $name ( @{ $hostnames->{$ip} } ) {

        # get a list of IPs returned by $name (ideally should only be one)
        my @resolved_ips = forward_lookup($name);

        # too many resolved IPs!
        if ( scalar(@resolved_ips) > 1 ) {
            push @{ $bad_reverses->{'multipleforwards'} },
                "$name forwards to multiple IPs(" . join( ', ', @resolved_ips ) . ")!";

            # Not enough resolved IPs!
        } elsif ( scalar(@resolved_ips) == 0 ) {
            push @{ $bad_reverses->{'nodnsentry'} }, "$ip reverses to $name, but $name doesn't have a DNS entry!";

            # First resolved IP isn't what we expect
        } elsif ( $resolved_ips[0] ne $ip ) {
            push @{ $bad_reverses->{'resolvemismatch'} },
                "$ip resolves as $name, but $name resolves as " . join( ', ', @resolved_ips ) . "!";
        }
    } ## end foreach my $name ( @{ $hostnames...})

    #return our list of bad reverses
    return $bad_reverses;
} ## end sub check_reverse_match


##################################################
##
## Parse a given datastructure and sort entries 
## into three buckets:
##    * IP with multiple reverses ($ip_hosts)
##    * multiple reverses associated with same 
##      hostname ($host_ips) (this happens often 
##      with split horizon DNS)
##    * IP with no reverses found
##
##################################################
sub interpret_reverses {
    my ($ip_dns_records) = @_;
    my $ip_hosts;    # ip with multiple reverses
    my $host_ips;    # multiple reverses pointing to the same hostname
    my $no_reverse;
    foreach my $host (@$ip_dns_records) {
        my @names = @{ $host->{'names'} };
        my $ip    = $host->{'ip'};
        foreach my $name (@names) {
            if ( !defined $host_ips->{$name} ) {
                $host_ips->{$name} = [$ip];
            } else {

                # This usually should never be hit- if it is, then
                # multiple reverses point to the same host.
                $host_ips->{$name} = [ @{ $host_ips->{$name} }, $ip ];
            } ## end else [ if ( !defined $host_ips...)]
        } ## end foreach my $name (@names)

        # If someone has too many reverses
        if ( scalar(@names) > 1 ) {
            $ip_hosts->{$ip} = \@names;

            # ...or if they have no reverses
        } elsif ( scalar(@names) == 0 and scalar $host->{'alive'} == 1 ) {
            push @$no_reverse, { 'ip' => $ip, 'hostname' => $host->{'hostname'} };
        }

        # printing this lets us know that we're still running.
        print ".";
    } ## end foreach my $host (@$ip_dns_records)

    #return our three new data structures for interpretation.
    return ( $ip_hosts, $host_ips, $no_reverse );
} ## end sub interpret_reverses


##################################################
##
## Given an IP Range, return the list of it's IP 
## addresses. This is what we plan on scanning 
## later.
##
##################################################
sub create_ip_list {
    my (@ranges) = @_;
    my @ips;
    foreach my $range (@ranges) {
        my $block = Net::Netmask->new($range);
        my $broadcast = $block->broadcast;
        push @ips, $block->enumerate();
        @ips = grep  { ! /^$broadcast$/ } @ips;
    }
    @ips = sort @ips;
    return @ips;
} ## end sub create_ip_list


##################################################
##
## Given a list of IP addresses, Do a reverse 
## lookup on each and return the aggregated 
## results as a datastructure Note that this is 
## one of two multithreaded sections in the code.
##
##################################################
sub scan_reverse_lookups {
    my ( $config, $iplist ) = @_;

    # This app is threaded so you can do multiple lookups at the same time-
    # useful when scanning thousands of IP addresses.
    my @threadIDs;
    my $pool = Thread::Pool::Simple->new(
        load => $config->val( 'Threading', 'load' ),
        min  => $config->val( 'Threading', 'min' ),
        max  => $config->val( 'Threading', 'max' ),
        do   => [ \&reverse_lookup ],
    );

    # Toss the lookups into the queue to be processed by the pool
    for my $ip (@$iplist) {
        push @threadIDs, $pool->add( $config, $ip );
    }

    # Wait until everything is looked up
    $pool->join();

    # Gather up all of our results into an array
    my @ip_records;
    foreach my $id (@threadIDs) {
        my ($host) = $pool->remove($id);
        push @ip_records, $host;
    }

    #return a reference to our array of records
    return \@ip_records;
} ## end sub scan_reverse_lookups


##################################################
##
## Given our ips with multiple reverses, sort 
## through the results, then sort the results 
## into three buckets Multiple forwards, no DNS 
## entry, and resolution mismatch.
##
##################################################
sub scan_reverse_matches {
    my ( $config, $ip_w_host ) = @_;
    print "\n checking reverse matches\n";
    my @threadIDs = [];
    my $pool      = Thread::Pool::Simple->new(
        load => $config->val( 'Threading', 'load' ),
        min  => $config->val( 'Threading', 'min' ),
        max  => $config->val( 'Threading', 'max' ),
        do   => [ \&check_reverse_match ],
    );
    for my $ip ( keys %$ip_w_host ) {
        push @threadIDs, $pool->add( $mainconfig, $ip, $ip_w_host );
    }

    # Wait until everything is looked up
    $pool->join();

    my ( $multipleforwards, $nodnsentry, $resolvemismatch ) = ( [], [], [] );

    # Cycle through the results and categorize it.
    foreach my $id (@threadIDs) {
        my ($host) = $pool->remove($id);

        if ( defined $host->{'multipleforwards'} and scalar @{ $host->{'multipleforwards'} } > 0 ) {
            push @$multipleforwards, @{ $host->{'multipleforwards'} };
        }
        if ( defined $host->{'nodnsentry'} and scalar @{ $host->{'nodnsentry'} } > 0 ) {
            push @$nodnsentry, @{ $host->{'nodnsentry'} };
        }
        if ( defined $host->{'resolvemismatch'} and scalar @{ $host->{'resolvemismatch'} } > 0 ) {
            push @$resolvemismatch, @{ $host->{'resolvemismatch'} };
        }
    } ## end foreach my $id (@threadIDs)

    @$multipleforwards = sort @$multipleforwards;
    @$nodnsentry       = sort @$nodnsentry;
    @$resolvemismatch  = sort @$resolvemismatch;
    return ( $multipleforwards, $nodnsentry, $resolvemismatch );
} ## end sub scan_reverse_matches

# End #
