if (${?CLASSPATH} == 0) then
    setenv CLASSPATH
endif
setenv CLASSPATH ${CLASSPATH}:.:lib/iaik_jce.jar
