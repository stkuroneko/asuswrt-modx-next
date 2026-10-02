EXEC = qos_run qos_portbased_run

all: $(EXEC) 

romfs:
	$(STRIP) qos_run
	$(STRIP) qos_portbased_run
	$(STRIP) qos_run.obj
	$(ROMFSINST) -e CONFIG_RALINKAPP_SWQOS /bin/qos_run
	$(ROMFSINST) -e CONFIG_RALINKAPP_SWQOS /bin/qos_portbased_run

clean:
	-rm -f $(EXEC) *.o

