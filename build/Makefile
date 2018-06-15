RESOURCES = \
auth\
registration\
user\

auth_dep = ./../api/auth_jwt/*
auth_pip = jose cerberus requests

registration_dep = ./../api/registration/*
registration_pip = cerberus bleach

all: $(RESOURCES)
	@echo 'finished build all'

.SECONDEXPANSION:
$(RESOURCES): %: Makefile $$(%_dep)
	if not exist output mkdir output
	if not exist $@ mkdir $@
	pip install $($@_pip) -t ./$@

#copy source files and local dependencies
	xcopy "$($@_dep)" "$@" /S /I
	#cp -R ./../model ./$@
	#cp -R ./../util ./$@

#additional steps for user build
#	if [ "$@" = "user" ]; then\
		mkdir -p user/lib;\
		cp /usr/lib64/libffi.so ./user/lib/libffi-72499c49.so;\
	fi

#package and clean
	cd $@;zip -r lambda_$@.zip ./
	mv $@/lambda_$@.zip ./output
	@echo finished $@ build


.PHONY:clean
clean:
	rm -Rf $(RESOURCES) output
