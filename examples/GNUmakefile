# $assl$

SUBDIRS= client server

all: $(SUBDIRS)

clean:
	@for i in $(SUBDIRS); do $(MAKE) -C $$i/ clean; done

$(SUBDIRS): 
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)
