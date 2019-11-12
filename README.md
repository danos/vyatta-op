The Debian Package vyatta-op
----------------------------

This package has the Vyatta operational command completion script and
base template tree. The default root of this tree is:
     /opt/vyatta/share/vyatta-op/templates

Each directory within this tree is a respective command line argument;
for example, the .../templates/show/interfaces/ethernet directory
completes the command line "show interfaces ethernet". Thus, the
directory name is generally equivalent to the command or argument
name.  The only exception are directories named "node.tag"; these
represent dynamic or variable command arguments. For example,
.../templates/show/interfaces/ethernet/node.tag completes the active
system interfaces like "show interfaces ethernet eth0".

Every template directory must have one and only one file named
"node.def". This file defines the node help string and run command,
like .../templates/show/interfaces/node.def:

help: "Show network interface information"
run: ${vyatta_bindir}/vyatta-show-interfaces.pl --show

Notes:
	- field tags (i.e. "help:" and "run:") must be at the start of line
	- try to limit help strings to 64 characters
	- run commands may span multiple lines but subsequent lines must
	  not begin with "WORD:"

The run command is an evaluated shell expression that may contain the
positional command line argument variables (i.e. $1, $*, $@).
However, since the command itself, is evaluated through an aliased
function, $1 is the command name rather than the usual $0. So, the
command "show interfaces ethernet eth0" would evaluate the respective
run command with $4 == eth0.

The variable argument .../node.tag/node.def files may also define an
"allowed" field. This is a misnomer since it's really used to produce
a list of possible completions or additional help rather than what is
allowed during execution. The fields contents are evaluated shell
expression that outputs (stdout) the list of possible completion
values or symbolic help of the pattern '<*>'. A blank or missing
"allowed" field means that there is no completion for the respective
node; for such nodes a '*' placeholder tag is displayed with the help
text.

Examples:

.../templates/show/interfaces/ethernet/node.tag/node.def

help: Show specified ethernet interface information
allowed: ${vyatta_sbindir}/vyatta-interfaces.pl --show ethernet
run: ${vyatta_bindir}/vyatta-show-interfaces.pl --intf="$4"

 -- Tom Grennan <tgrennan@vyatta.com>  Mon, 17 Sep 2007


