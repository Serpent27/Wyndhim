# ----------------------------
# Set NAME to the program name
# Set ICON to the png icon file name
# Set DESCRIPTION to display within a compatible shell
# Set COMPRESSED to "YES" to create a compressed program
# ----------------------------

NAME        ?= WINDHYM
COMPRESSED  ?= NO
ICON        ?= icon.png
DESCRIPTION ?= "Windhym Encryption Algorithm"

# ----------------------------

include $(CEDEV)/include/.makefile
