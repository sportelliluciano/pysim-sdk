# PySIM SDK

Conjunto de herramientas para armar una simulación con PySIM.

## Herramientas

Este paquete incluye varios tipos de interfaces de red para interactuar entre distintos dispositivos
o con el sistema operativo host mediante interfaces TUN/TAP.

A su vez, en caso de querer realizar una simulación con QEMU, se provee un adaptador para poder
definir comandos y eventos fácilmente. Este adaptador debe utilizarse en conjunto con el componente
de ESP-IDF que se encuentra en este repositorio: https://github.com/sportelliluciano/i4a-pysim-idf.

## Dockerfiles

En caso de querer simular con QEMU, se provee un archivo `Dockerfile.qemu` que crea una imagen de
Docker con el fork de QEMU provisto por Espressif ya instalado y listo para usar, así como también
el acceso a PySIM mediante sockets de Unix. Esta Dockerfile necesita también del archivo `docker-entrypoint.sh` para funcionar.
