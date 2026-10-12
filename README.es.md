# hivescope-bunker

**[English](README.md) · [Español](README.es.md)**

Un firmador remoto [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) para **una cuenta de Nostr**, que corre en **tu propio servidor**. Las aplicaciones
que usas (un cliente como [Quill](https://github.com/rzazo24/quill), un asistente como [nostrclaw](https://github.com/rzazo24/nostrclaw), el panel de un relé) le piden
que firme; cada una puede firmar **solo lo que necesita**, y tu clave no sale de este proceso.

Existe porque un firmador de móvil que depende de despertarse con un aviso puede fallar en el peor momento. Tener el tuyo es más fiable, pero es un intercambio real:
**tu clave vive (cifrada) en un servidor y no en el llavero de tu móvil.** Lee [contra qué no protege](#contra-qué-no-protege) antes de usarlo.

## Cómo protege la clave

- La clave se guarda **cifrada** ([NIP-49](https://github.com/nostr-protocol/nips/blob/master/49.md): scrypt + XChaCha20-Poly1305), con permisos 0600 y una contraseña que eliges tú. Nunca se escribe en claro ni se imprime.
- Tras cada arranque el bunker está **bloqueado**. Lo desbloqueas a mano (`hivescope-bunker unlock`); la clave descifrada vive solo en memoria.
- Cada aplicación tiene su propia **conexión** con un **perfil**: qué tipos de evento puede firmar y cuántas firmas por hora. Todo lo demás se rechaza.

  | perfil | tipos | por hora | notas |
  |---|---|---|---|
  | `quill` | 0, 1, 3, 5, 6, 7, 9734, 10000, 10002 | 60 | perfil (Quill cambia solo la descripción), notas, borrar tus notas, lista de seguidos, reposts, reacciones, peticiones de zap (las paga tu monedero, nunca se publican), lista de silenciados (parte pública), lista de relés |
  | `nostrclaw` | 1, 5, 7, 10050 | 20 | notas, borrados, reacciones, lista de relés de mensajes privados |
  | `panel` | 27235 | 30 | solo el inicio de sesión NIP-98 de un panel, y solo para la dirección dada con `--url` |

- Los secretos de emparejamiento se guardan solo como **hashes**: el archivo de conexiones por sí solo no sirve para conectarse. Revocar una conexión la para en la siguiente petición.
- Las peticiones de cifrado y descifrado (`nip04_*`, `nip44_*`) y los métodos desconocidos se **rechazan**. Las peticiones viejas y los eventos repetidos se ignoran.
- **No abre ningún puerto.** El bunker se conecta hacia fuera con los relés; su socket de control es un socket unix (permisos 0600).
- Cada firma queda en el registro (tipo, aplicación, id corto), nunca el contenido.

## Instalación

Necesitas Go 1.25+ y un servidor Linux con systemd.

```bash
git clone https://github.com/rzazo24/hivescope-bunker && cd hivescope-bunker
CGO_ENABLED=0 go build -o hivescope-bunker .
./hivescope-bunker init      # te pide, en el terminal y sin mostrarlo, tu nsec y una contraseña (10+ caracteres)
```

`init` muestra el `npub` con el que va a firmar: **comprueba que es la cuenta correcta**. Después ponlo como servicio que arranca **bloqueado** (antes, edita las rutas y el usuario del archivo):

```bash
sudo cp deploy/hivescope-bunker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now hivescope-bunker
./hivescope-bunker unlock    # te pide la contraseña
```

El estado vive en `~/.hivescope-bunker` (o `$HIVESCOPE_BUNKER_DIR`): `key.ncryptsec`, `config.json`, `connections.json`, `control.sock`.
Los relés por defecto son `relay.hivescope.xyz` y `relay.damus.io`; cámbialos en `config.json`.

## Conectar una aplicación

```bash
./hivescope-bunker add quill-phone quill                 # imprime una dirección bunker:// UNA vez: es una contraseña
./hivescope-bunker add nostrclaw nostrclaw
./hivescope-bunker add panel panel --url https://tu-rele.example/admin/api/login
./hivescope-bunker list                                  # conexiones, tipos, último uso
./hivescope-bunker revoke quill-phone
./hivescope-bunker refresh quill-phone                   # tras una actualización que amplía un perfil: da a una conexión ya creada los tipos nuevos
```

Pega la dirección en la aplicación (nunca en un chat ni en una herramienta que la registre):

- **Quill**: *Yo › Conectar firmador › Pegar y conectar* (sirve cualquier dirección `bunker://`).
- **nostrclaw**: `node dist/index.js connect-bunker --claude nostrclaw-sign` en tu propio terminal. Un bunker aprueba por política y no una persona, así que sus firmas vuelven en milisegundos y nostrclaw las descartaría; pon `"minHumanApprovalMs": 0` en su `policy.json` (mira su README).
- **El panel de un relé con acceso por bunker** (como en [nostr-relay-khatru](https://github.com/rzazo24/nostr-relay-khatru)): pega la dirección en el inicio de sesión del panel.

Otros comandos: `lock` (olvidar la clave de la memoria ahora), `status`.

## Tras un reinicio

El servicio arranca **bloqueado**, así que nadie puede firmar hasta que ejecutes `./hivescope-bunker unlock` por SSH. Ese es el precio de no guardar la contraseña en el servidor.

## Copia de seguridad de la clave

Copia la única línea de `~/.hivescope-bunker/key.ncryptsec` (empieza por `ncryptsec1`) a un gestor de contraseñas. Está cifrada, así que guardarla es seguro; **la contraseña debe guardarse aparte.** Las conexiones no forman parte de la copia: vuelve a crearlas con `add`.

## Contra qué no protege

- Alguien con **root en la máquina mientras el bunker está desbloqueado** puede firmar dentro de los límites de cada conexión, y puede leer la clave de la memoria.
- Una contraseña débil: el archivo es tan fuerte como ella. Usa una larga.
- Una aplicación maliciosa que hayas emparejado. Por eso cada conexión tiene una lista corta de tipos y un límite por hora.

## Pruebas

```bash
go test ./...
```

La prueba de extremo a extremo arranca un relé real y un cliente NIP-46 real; necesita `RELAY_BIN` (una compilación de [nostr-relay-khatru](https://github.com/rzazo24/nostr-relay-khatru)) y se salta sin él.

## Licencia

MIT
