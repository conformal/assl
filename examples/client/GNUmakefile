# $assl$

SUBDIRS= blocking nonblocking

all: $(SUBDIRS)

clean:
	@for i in $(SUBDIRS); do $(MAKE) -C $$i/ clean; done

$(SUBDIRS): 
	$(MAKE) -C $@ $(MOO)

.PHONY: all clean $(SUBDIRS)
