# Negro Recon v0.10.3

- CORS por recurso reutiliza el contexto HTTP más reciente observado por Burp (cookies/Authorization y headers útiles), reemplazando únicamente `Origin` por el origen controlado de Negro.
- El resultado CORS queda visible dentro del propio recurso: status, ACAO, credentials y si la señal parece interesante.
- El popup de finalización muestra el resultado concreto de CORS en vez de limitarse al delta de inventario.
- Se corrigió un caso donde la UI podía quedarse en “Terminado. Actualizando resultados…” si `sessionStorage` rechazaba el payload del job.
