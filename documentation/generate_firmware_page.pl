#!/usr/bin/perl -w

####################################################################
#                    Generate Firmware Page                        #
# Author: Jesse Morgan                                             #
# Purpose: List firmware versions, order by hardware               #
# classification and highlight up-to-date instances.               #
####################################################################

use lib '../';
use strict;
use warnings;
use Carp;
use Config::IniFiles;
use Data::Dumper;
use MorgInvSys;
use Net::LDAP;
use Net::Netmask;
use Thread::Pool::Simple;
use Time::Duration;

my $config = Config::IniFiles->new( -file => "../configs/config.ini" ) or croak "Could not open your config!";
my $title = "Current Firmware Status";
my $starttime = time();    # Overall script starttime

###################################################################
##  Generate page

my @content = &generate_header();
push @content, &generate_content($config);
push @content, &generate_footer($starttime);

write_page_to_wiki( $config, "Current Firmware Status", @content );

#############################################
#############################################
#############################################
#############################################


##################################################
##
## Generate the content of the page. 
##
##################################################
sub generate_content {
    my ($config)=@_;

    my $filter = "(&".$config->val('LDAP Filters','active hosts')."(!(makename=VMWare*))(OS=*Linux*)(cn=*))";
    my $results = ldap_search($config, $filter);
    my $count = $results->count();

    my @content=firmware_page_header($results->count());

    foreach my $host ( $results->sorted('MakeName','ModelNumber','cn','FirmwareVersion') ){
        my $firmstruct=parse_firmware($host);
        push @content, format_host_firmware($host, $firmstruct);
    }
    push @content, &generate_current_firmware_list($config);
    return @content;
}


##################################################
##
## Generate the description and legend for the
## page as well as the head of the table.
##
##################################################
sub firmware_page_header {
    my ($count) = @_;
    my @content;
    push @content, "Firmware versions based on the best available information on http://h18000.www1.hp.com/products/blades/bladesystemupdatestable.html";
    push @content, "and by manually searching the HP site. Please update the config.ini if these numbers change and please please please let me know if "
                 . "HP has an api where we can dynamically pull this data.";
    push @content, "";
    push @content, "LEGEND: {color:green}Up To Date{color},{color:red}New Version Available{color},{color:gray}Version Untracked{color}";
    push @content, "Newest known versionIDs are in parenthesis.";
    push @content, "";
    push @content, "$count Servers found (active linux hosts that are not VMs).";
    push @content, "|| Name || Description || Manufacturer || Model || Nic || Storage || Bios || Power || iLO ||";
    return @content;
} ## end sub firmware_page_header


##################################################
##
## Take a given host and firmware structure, and
## properly format it for use in a wiki table.
##
##################################################
sub format_host_firmware{
    my ($host,$firmstruct)=@_;
    
    my $hostline=   "| ".$host->get_value('cn').
                   " | ".join("\n",sort $host->get_value('description')).
                   " | ".($host->get_value('makeName')||'unknown').
                   " | ".($host->get_value('modelNumber')||'unknown').
                   " | ".join("\n",sort @{$firmstruct->{'nic'}}).
                   " | ".join("\n",sort @{$firmstruct->{'storage'}}).
                   " | ".join("\n",sort @{$firmstruct->{'bios'}}).
                   " | ".join("\n",sort @{$firmstruct->{'power'}}).
                   " | ".join("\n",sort @{$firmstruct->{'ilo'}}).
                   " | ";
    return $hostline;
}


##################################################
##
## Read firmware data from a host's ldap entry
## and parse the firmware info into a structure.
##
##################################################
sub parse_firmware {
    my ($host)=@_;
    my $firmstruct={
                    'nic'=>[],
                    'storage'=>[],
                    'bios'=>[],
                    'power'=>[],
                    'ilo'=>[],
                    };
    if (defined $host->get_value('firmwareVersion')){
        foreach my $firmware ( ( $host->get_value('firmwareVersion'))){
            if ($firmware!~/None Detected/){
                if     ($firmware=~/^NIC /i     ){
                            push @{$firmstruct->{'nic'}},   &format_nic($config,$firmware);
                }elsif ($firmware=~/^Storage /i ){
                            push @{$firmstruct->{'storage'}},&format_firmware($config,$firmware, '^Storage ');
                }elsif ($firmware=~/^bios /i    ){
                            push @{$firmstruct->{'bios'}},  &format_firmware($config,$host->get_value('modelNumber')." $firmware", '');
                }elsif ($firmware=~/^power /i   ){
                            push @{$firmstruct->{'power'}}, &format_firmware($config,$firmware, '^Power ');
                }elsif ($firmware=~/^ilo/i      ){
                            push @{$firmstruct->{'ilo'}},   &format_firmware($config,$firmware, '');
                }
            }
        }
    }
    return $firmstruct;
}

##################################################
##
## Generate a small table containing a list of 
## all the various types of firmware that we 
## track in our config.ini file.
##
##################################################
sub generate_current_firmware_list{
    my ($config)=@_;
    my @content;
    push @content,"";
    push @content,"||firmware Type||Current Version||";
    foreach my $version ($config->Parameters('Firmware')){
        push @content,"| ".$version." | ".$config->val("Firmware",$version)."|";
    }
    return @content;
}

##################################################
##
## Format the nic field with the proper color 
## and value.
##
##################################################
sub format_nic {
    my ( $config, $firmware ) = @_;
    $firmware =~ s/^NIC //i;
    my $result = "{color:gray}$firmware (unknown){color}";
    my $found;    # TODO there should be some logic to determine if this is found or not.
    if ( defined $found ) {
        $result = "{color:red}$firmware \n($found){color}";
    }
    return $result;
}


##################################################
##
## Generic formatting with the proper color and
## value.
##  - Green if found and up to date
##  - Red if found and out of date
##  - Gray if not tracked.
##
##################################################
sub format_firmware {

    #FIXME this method is ugly.
    my ( $config, $firmware, $filter ) = @_;
    $firmware =~ s/$filter//i;
    my $result = "{color:gray}$firmware (unknown){color}";
    foreach my $firmware_type ( $config->Parameters('Firmware') ) {
        if ( $firmware =~ /$firmware_type/i ) {
            my $vID = $config->val( 'Firmware', $firmware_type );
            if ( $firmware =~ /$vID$/ ) {
                return "{color:green}$firmware"."{color}";
            } else {
                $result = "{color:red}$firmware \n($vID){color}";
            }
        }
    }
    return $result;
}



