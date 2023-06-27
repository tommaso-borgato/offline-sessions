# offline-sessions

## porting to openshift
https://access.redhat.com/documentation/en-us/red_hat_jboss_enterprise_application_platform/8-beta/html-single/using_jboss_eap_on_openshift_container_platform/index#eap-operator-for-safe-transaction-recovery_default

## build on bare metal
TODO

## run on bare metal

cd offline-sessions/offline-access-portal
offline-sessions/offline-access-portal/target/server/bin/standalone.sh -Djboss.node.name=wildfly1

cd offline-sessions/database-service
offline-sessions/database-service/target/server/bin/standalone.sh -Djboss.node.name=wildfly2

http://0.0.0.0:8180/offline-access-portal/app
