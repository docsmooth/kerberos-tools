#!/usr/bin/perl

use strict;
use warnings;

my $ktfile=shift;
my $upn=shift;
my $realm=shift;
my $kvno=shift;
my $password = join("", @ARGV);

$realm=uc($realm);
open(my $kt, ">", "$ktfile") || die "can't open $ktfile for writing! $!";

print $kt "clear_list\n";

my @parts=split(/@/, $upn);
my $dom=$parts[1];
my $usr=$parts[0];
my $salt=uc($dom)."host".lc($usr);

my @enctypes=("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "arcfour-hmac");
foreach my $kvn (($kvno, $kvno-1)) {
foreach my $enc (@enctypes) {
    foreach my $domain ((uc($dom), lc($dom))) {
        foreach my $user ((uc($usr), lc($usr))) {
            print $kt "addent -password -p $user/$domain\@$domain -k $kvn -e $enc\n";
            print $kt "$password\n";
            print $kt "addent -password -p $user/".lc($domain)."\@$domain -k $kvn -e $enc\n";
            print $kt "$password\n";
            print $kt "addent -password -p $user/$domain\@$domain -k $kvn -e $enc -s $salt\n";
            print $kt "$password\n";
            print $kt "addent -password -p $user/".lc($domain)."\@$domain -k $kvn -e $enc -s $salt\n";
            print $kt "$password\n";
            print $kt "addent -password -p $user\@$domain -k $kvn -e $enc\n";
            print $kt "$password\n";
            print $kt "addent -password -p $user\@$domain -k $kvn -e $enc -s $salt\n";
            print $kt "$password\n";
        }
    }
    print $kt "addent -password -p $upn -k $kvn -e $enc\n";
    print $kt "$password\n";
}}
print $kt "write_kt $ktfile.keytab\n";
close $kt;
