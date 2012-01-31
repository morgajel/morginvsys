#!/usr/bin/perl -w
####################################################################
#             Current Hardware Breakdown Reports                   #
# Author: Jesse Morgan                                             #
# Purpose: Interrogate LDAP Inventory to identify and sort         #
# hardware, then generate pages with breakdowns on each type of    #
# hardware and statistics on the servers.                          #
####################################################################
use lib '../';
use strict;
use warnings;
use Carp;
use Config::IniFiles;
use Data::Dumper;
use MorgInvSys;
use Net::LDAP;
use Switch;
use Thread::Pool::Simple;
use Time::Duration;

my $config = Config::IniFiles->new( -file => "../configs/config.ini" ) or croak "Could not open your config!";

my $starttime=time();

my %models=gather_models($config);

generate_children_pages($config,%models);


generate_main($config,$starttime,%models);


#############################
#############################
#############################
#############################


##################################################
##
## Given the list of models, generate a child 
## page for each model.
##
##################################################
sub generate_children_pages{
    my ($config,$starttime,%models)=@_;

    foreach my $modelname (sort keys %models){
        my $starttime=time();
        generate_child_page($config,$starttime,$modelname);
    }
}


##################################################
##
## Given the list of models, generate a child 
## page for each model.
##
##################################################
sub generate_child_page {
    my ($config,$starttime,$modelname)=@_;
    my $filter="(&".$config->val('LDAP Filters','active hosts')."(modelNumber=*$modelname*))";
    my $results = ldap_search($config, $filter);

    my (%locations, $generations);
    my @content=generate_child_header($modelname); 

    foreach my $host ( $results->entries() ){
        my ($entry,$generation)=generate_host_line($host);
        push @content, $entry;
        $generations=increment_generation($generation, $generations );
        $locations{$host->get_value('l')}=increment_location($locations{ $host->get_value('l') } );
    }

    push @content, generate_child_footer($starttime,$results->count(),location_breakdown(%locations),generation_breakdown($generations));
    print Dumper @content;
    write_page_to_wiki($config, "$modelname Breakdown",@content);
}


##################################################
##
## Display the regular Confluence footer as well
## as a specifc hardware breakdown footer.
##
##################################################
sub generate_child_footer {
    my ($starttime,$count,$locations,$generations)=@_;
    my @content;
    push @content,  "|| Total Servers: {color:#000000} $count {color} ".
                    "||  ||  ||  ||  || ".
                    "|| Total Locations:\n {color:#000000} $locations {color} ".
                    "|| Total Generations:\n {color:#000000} $generations {color}".
                    "||";
    push @content, generate_footer($starttime);
    return @content;
}


##################################################
##
## Display the regular Confluence header as well
## as a specifc hardware breakdown header.
##
##################################################
sub generate_child_header {
    my ($modelname)=@_;
    my @content=generate_header(); 
    push @content, "h2.Hardware Breakdown for Active $modelname";
    push @content, "|| Server || Descriptions || Primary IP || ILO || CPU || Memory || Network || Location || Generation ||";
    return @content;
}


##################################################
##
## Sort and prettify the locations and counts
## into a single, newline-separated string..
##
##################################################
sub location_breakdown {
    my (%locations)=@_;
    my @locationBreakdown;
    foreach my $location (sort keys %locations){
        my $count=$locations{$location}||'undefined!';
        push @locationBreakdown, "$count $location";
    }
    return join("\n", @locationBreakdown);
}


##################################################
##
## sort and prettify the generations and counts
## into a single, newline-separated string..
##
##################################################
sub generation_breakdown {
    my ($generations)=@_;
    my @generationBreakdown;
    foreach my $gen (sort keys %$generations){
        push @generationBreakdown, $generations->{$gen}." $gen";
    }
    return join("\n", @generationBreakdown);
}


##################################################
##
## Generate the line entry for a host, and 
## return the entry and the hardware generation.
##
##################################################
sub generate_host_line {
    my ($host)=@_;
    my @content;
    my ($model,$generation)= split_model_generation($host->get_value('modelNumber'));

    my $entry=  " | ".($host->get_value('cn')||"n/a").
                " | ".($host->get_value('Description')||"n/a").
                " | ".($host->get_value('primaryIPHostNumber')||"n/a").
                " | ".
                " | ".($host->get_value('CPU')||"n/a").
                " | ".($host->get_value('memorySize')||"n/a").
                " | n/a".
                " | ".($host->get_value('l')||"n/a").
                " | ".($generation||"n/a").
                " | ";
    push @content, $entry;

    return ($entry,$generation);
}



##################################################
##
## Generate the main page for the current
## hardware breakdown pages.
##
##################################################
sub generate_main{
    #TODO This needs to be refactored, it's ugly.
    my ($config,$starttime,%models)=@_;

    my @content=generate_header(); 

    push @content, "h2.Hardware Models";
    push @content, "|| Model || Active Server Count || Breakdown||";
    my $totalcount=0;
    foreach my $model (sort keys %models){
        $totalcount+=$models{$model}->{'count'};
        my @breakdown;
        foreach my $generation (sort keys %{$models{$model}->{'generation'}}){
            push @breakdown, $models{$model}->{'generation'}->{$generation} ." $generation";
        }
        push @content,  " | [$model |CRH:$model Breakdown] | ".$models{$model}->{'count'}." | ".join(", ",@breakdown)." | " ;
    }
    
    push @content,  "|| Total Model Types: {color:#000000}".scalar(keys %models)."{color} "
                   ."|| Total Active Server Count: {color:#000000}".$totalcount."{color} "
                   ."|| "
                   ."||";

    push @content, generate_footer($starttime);
    
    write_page_to_wiki($config, "Current Hardware Breakdown" ,@content);
}


##################################################
##
## Examine all active hosts, gather their model
## numbers the given model name.
##
##################################################
sub gather_models{
    my ($config)=@_;
    # return a result set of all hosts
    my $results = ldap_search($config,$config->val('LDAP Filters','active hosts'));

    my %models;
    foreach my $host ( $results->entries() ){
        my $model=$host->get_value('modelNumber')||'UNKNOWN';
        %models=categorize_model($model,%models);
    }
    return %models;
}


##################################################
##
## Increment the proper model and generation for
## the given model name.
##
##################################################
sub categorize_model{
    my ($model,%models)=@_;
    my $generation;

    ($model,$generation)=split_model_generation($model);
    # Increment that model's count
    $models{$model}=increment_model($models{$model});
    my $gen=$models{$model}->{'generation'};
    $models{$model}->{'generation'}=increment_generation($generation, $models{$model}->{'generation'} );
    return %models;
}


##################################################
##
## Split modelname into a model and generation.
##
##################################################
sub split_model_generation {
    my ($model)=@_;
    my $generation;
    # We currently only document three hardware types, but this would be trivial to improve
    if (    
            $model=~/(Interconnect Switch)/i or 
            $model=~/(ProLiant [^ ]+) (.*)/i or 
            $model=~/(AlphaServer [^ ]+) (.*)/i or 
            $model=~/(eserver xSeries [^ ]+) -\[(.*)\]-/){
        $model=$1;
        $generation=$2||undef;
    }
    return ($model,$generation);
}


##################################################
##
## Update a location count.
##
##################################################
sub increment_location {
    my ($location)=@_;
    if ( ! defined $location ){
        $location=1;
    }else{
        $location+=1;
    }
    return $location;
}


##################################################
##
## Update a generation count.
##
##################################################
sub increment_generation {
    my ($generation,$generations)=@_;
    if (defined $generation){
        if ( ! defined $generations->{$generation} ){
            $generations->{$generation}=1
        }else{
            $generations->{$generation}+=1
        }
    }
    return $generations;
}


##################################################
##
## Update a model hash count and generate a 
## generation if it doesn't exist.
##
##################################################
sub increment_model{
    my ($model)=@_;
    if (! defined $model){
        $model->{'count'}=1;
        $model->{'generation'}={};
    }else{
        $model->{'count'}+=1;
    }
    return $model;
}
