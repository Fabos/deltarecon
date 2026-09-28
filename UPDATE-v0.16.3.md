# Negro Recon v0.16.3

Hotfix de entrega Negro → Burp Repeater.

- El poller del bridge usa una llamada HTTP síncrona en su hilo dedicado para evitar futures fallidos sin observar.
- Logs de cada poll: status HTTP, longitud de body y bandera pending.
- Items `claimed` sin ACK expiran a `error` tras 30 segundos para evitar reenvíos y pestañas duplicadas; basta pulsar Enviar de nuevo.
- Logs seguros de claims del backend.
- No se registran cuerpos HTTP ni secretos en los logs.
