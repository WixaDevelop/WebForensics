"""Excel (.xlsx) exporter with a summary + glossary sheet.

Each artifact lands on its own sheet with proper headers, freeze panes
and an auto-filter. A leading "Resumen" sheet aggregates counts per
profile, a "Glosario" section documents every artifact type, and a
"Hallazgos" section surfaces automatic statistics — top hosts,
categories, encrypted credentials, downloaded executables and so on.

All timestamps in the workbook are rendered in :data:`REPORT_TZ`
(UTC-5) so the analyst doesn't have to mentally convert from UTC.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

from data.models import ARTIFACT_KINDS, ProfileBundle
from exporters.base import ExporterBase


# Single source of truth for the reporting timezone. UTC-5 covers
# Ecuador / Colombia / Peru / Eastern Standard Time (no DST). All
# datetimes the exporter writes pass through ``_to_local_dt`` and end
# up converted to this offset so Excel doesn't show raw UTC.
REPORT_TZ = timezone(timedelta(hours=-5))
REPORT_TZ_LABEL = "UTC-5"

# Names of every extra (non-bundle) store table we can export. Kept in
# this order so the workbook layout is predictable.
EXTRA_TABLES: tuple[str, ...] = (
    "search_terms",
    "accounts",
    "messages",
    "tokens",
    "user_agents",
    "findings",
    "iocs",
    "ioc_hits",
    "os_artifacts",
    "source_files",
    "domain_intel",
    "tags",
)

EXTRA_INTERPRETATIONS: dict[str, str] = {
    "search_terms": (
        "Lista de TODO lo que se buscó en Google, Bing, DuckDuckGo, YouTube, Twitter/X, etc. "
        "La app lee las URLs del historial, identifica cuáles son de un buscador y extrae "
        "exactamente lo que se escribió en la cajita de búsqueda. "
        "Ej: si se buscó 'precio iphone 15' en Google, aparece una fila con motor='google', "
        "consulta='precio iphone 15' y la fecha de la búsqueda. "
        "Es muy útil porque resume directamente QUÉ se andaba investigando, sin tener que leer "
        "URLs largas en el historial."
    ),
    "accounts": (
        "Cuentas en servicios online identificadas en este perfil de navegador. La app revisa "
        "cookies y datos de los sitios buscando IDs conocidos. "
        "Ej: si en Facebook está la cookie 'c_user=100012345', se registra una cuenta de "
        "Facebook con ese ID; si en GitHub la cookie dice 'user_session=...', se registra el "
        "usuario de GitHub. "
        "La presencia de una cuenta aquí indica que en este navegador HABÍA tokens o cookies "
        "de esa cuenta — no implica que la cuenta sea de la persona dueña del equipo (otra "
        "persona pudo haber iniciado sesión en este navegador)."
    ),
    "messages": (
        "Mensajes de chat rescatados de aplicaciones web como WhatsApp Web, Discord, "
        "Telegram Web, Slack y Microsoft Teams. Estas apps guardan los mensajes en una base de "
        "datos interna del navegador (IndexedDB) para que aparezcan rápido al volver a entrar. "
        "Ej: una fila con app='whatsapp', chat='Familia', remitente='Mamá' y body='nos vemos a "
        "las 6' indica un mensaje que estaba almacenado localmente. "
        "La recuperación es 'mejor esfuerzo' — a veces los mensajes salen incompletos porque la "
        "estructura interna de IndexedDB es compleja."
    ),
    "tokens": (
        "Tokens de autenticación encontrados en este perfil. Un token es como un 'pase digital' "
        "que el navegador lleva en cada petición para no tener que volver a pedir contraseña. "
        "Es lo que hace que una app móvil te deje entrar sin loguear cada vez. "
        "Ej: un token JWT decodificable puede revelar 'esto es de la cuenta manuel@ejemplo.com, "
        "tiene permisos de lectura y expira el 2026-12-31'. "
        "Que aparezca un token aquí NO le da acceso al revisor a esa cuenta — solo documenta "
        "que en este navegador había uno."
    ),
    "user_agents": (
        "Cadenas con las que el navegador se identificó ante los servidores web. Sirven para "
        "detectar uso desde DIFERENTES dispositivos o configuraciones. "
        "Ej: 'Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120' = Chrome en Windows de 64 bits; "
        "'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari' = Safari en iPhone. "
        "Si en un mismo perfil aparecen User-Agents muy diferentes (escritorio + móvil), suele "
        "indicar sincronización del navegador entre varios dispositivos."
    ),
    "findings": (
        "Alertas automáticas del 'detector de cosas raras' de la app. Revisa los datos buscando "
        "patrones sospechosos. "
        "Ej: si el historial tiene un hueco de varios días pero las cookies de sesión siguen "
        "vivas, podría ser que alguien borró el historial pero olvidó cerrar sesión. "
        "Otros ejemplos: URLs con fecha en el futuro, dominios que solo aparecen en filas "
        "recuperadas, contadores en cero con cookies presentes. "
        "Las filas con severidad 'Crítica' o 'Alta' son las que conviene revisar primero."
    ),
    "iocs": (
        "Lista de IOCs (Indicadores de Compromiso) que el analista cargó en la sesión ANTES "
        "del análisis. Son 'valores malos conocidos' — por ejemplo, una lista de dominios "
        "asociados a malware, de IPs de servidores de control de botnets, o de huellas SHA-256 "
        "de archivos peligrosos. "
        "Ej: el analista carga la lista 'evil-domains.csv' que contiene 500 dominios sospechosos; "
        "esta hoja muestra esos 500 dominios con su nivel de severidad. "
        "La hoja 'IOC matches' lista cuáles de estos efectivamente APARECIERON en este caso."
    ),
    "ioc_hits": (
        "Las coincidencias — donde los IOCs cargados se encontraron en los datos del caso. "
        "Cada fila significa: 'El valor X (marcado como sospechoso) APARECE en este caso, en el "
        "campo Y de la hoja Z'. "
        "Ej: una fila puede decir: 'IOC malware.example.com → coincidió con campo url en la "
        "hoja history'. "
        "Son los datos más urgentes de revisar — son justamente lo que se buscaba detectar."
    ),
    "os_artifacts": (
        "Información extraída del sistema operativo Windows (no del navegador), recolectada "
        "para corroborar la actividad desde otra perspectiva. "
        "Ej: si en el Registro de Windows hay una entrada de 'TypedURLs' que dice 'bbva.com', "
        "Windows recuerda que esa URL fue escrita en el Explorador o en el campo 'Ejecutar' — "
        "esto refuerza lo que dice el historial del navegador. "
        "Incluye: Registro de Windows (URLs y rutas escritas), Prefetch (cuándo se ejecutó el "
        "binario del navegador), accesos directos LNK recientes, archivo hosts y caché DNS."
    ),
    "source_files": (
        "Cadena de custodia: lista de TODOS los archivos que WebForensics leyó durante la "
        "extracción, con la huella criptográfica de cada uno (SHA-256). "
        "Ej: una fila puede decir 'C:\\Users\\juan\\AppData\\...\\History → SHA-256 7e2c3a8f...'. "
        "El SHA-256 prueba que ese archivo no fue alterado: si dos archivos comparten SHA-256 "
        "son idénticos byte por byte; si cambia un solo byte, el SHA-256 cambia por completo. "
        "Esta hoja es la prueba técnica de QUÉ FUENTES alimentaron el resto del reporte."
    ),
    "domain_intel": (
        "Información extra de cada dominio web que apareció en el caso: quién lo registró, en "
        "qué país, qué proveedor lo aloja, y un nivel de riesgo calculado por la app. "
        "Ej: 'banco-falso-12345.tk → país=TK, registrar=desconocido, riesgo=alto' alerta sobre "
        "un dominio en una extensión gratuita (.tk) usada frecuentemente por sitios de phishing. "
        "Los datos vienen de un caché offline incluido en la app — no se consulta internet "
        "durante el análisis."
    ),
    "tags": (
        "Notas y etiquetas que un analista HUMANO escribió manualmente durante la revisión del "
        "caso dentro de la app. "
        "Ej: una fila puede decir 'history fila WF-00001234 → etiqueta: evidencia_clave, nota: "
        "verificar este pago'. "
        "A diferencia del resto de hojas (que son salidas automáticas), aquí están las "
        "OBSERVACIONES HUMANAS — lo que un revisor marcó explícitamente."
    ),
}

EXTRA_TABLE_HUMAN_NAMES = {
    "search_terms": "Búsquedas",
    "accounts": "Cuentas detectadas",
    "messages": "Mensajes IM",
    "tokens": "Tokens (JWT/OAuth)",
    "user_agents": "User Agents",
    "findings": "Hallazgos forenses",
    "iocs": "IOCs cargados",
    "ioc_hits": "IOC matches",
    "os_artifacts": "Artefactos del SO",
    "source_files": "Cadena de custodia",
    "domain_intel": "Enriquecimiento dominios",
    "tags": "Notas del analista",
}

try:  # pragma: no cover — optional dep, declared in requirements.txt
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.table import Table, TableStyleInfo
    _HAS_OPENPYXL = True
except Exception:  # noqa: BLE001
    _HAS_OPENPYXL = False


# ---------------------------------------------------------------------------
# Human-readable copy
# ---------------------------------------------------------------------------


# Descripción de cada hoja en estilo "for dummies": una analogía
# cotidiana al inicio + ejemplos concretos + una aclaración objetiva
# de lo que el dato NO prueba por sí solo. Las definiciones usan voz
# pasiva (sin afirmar quién hizo qué); los ejemplos van marcados con
# "Ej:" y son hipotéticos.
_ARTIFACT_INTERPRETATIONS: dict[str, str] = {
    "history": (
        "Es como la 'libreta de páginas visitadas' del navegador. Por cada dirección web (URL) "
        "abierta en este perfil queda una fila con: la dirección, el título de la página, "
        "cuántas veces se abrió y cuándo fue la última vez. "
        "Ej: si se entró 12 veces a 'facebook.com', aparece una sola fila para esa URL con "
        "Visitas registradas = 12 y la fecha del último acceso. "
        "La columna 'Tipo de visita' dice CÓMO se llegó cada vez (escribiendo la URL, click en "
        "un enlace, desde un favorito, etc.) — ver la leyenda al pie de este banner. "
        "Las filas marcadas como 'Fila recuperada de espacio borrado' son las que alguien intentó "
        "eliminar pero la app pudo rescatar de huecos internos del archivo del historial."
    ),
    "cookies": (
        "Cookies: archivos chiquitos que los sitios web dejan dentro del navegador para "
        "reconocerlo en visitas posteriores. Es lo que hace que cuando se entra a Facebook un "
        "día y al siguiente ya se está dentro sin volver a poner usuario y contraseña. "
        "Cada fila aquí es una cookie: el sitio que la dejó (columna 'Dominio'), su nombre, "
        "cuándo se creó y cuándo expira. "
        "Ej: una cookie con dominio '.google.com' y nombre 'SID' es típica de una sesión "
        "iniciada en Google. "
        "Una cookie por sí sola NO prueba que se haya hecho login en ese sitio: muchos sitios "
        "dejan cookies con solo cargarlos para fines publicitarios o de medición."
    ),
    "downloads": (
        "Lista de los archivos que el navegador descargó. Es lo mismo que aparece en "
        "chrome://downloads. Cada fila tiene: de qué URL vino, dónde se guardó en el disco "
        "(ej: 'C:\\Users\\juan\\Downloads\\contrato.pdf'), tamaño en MB y si terminó completa o "
        "se interrumpió. "
        "Que un archivo aparezca aquí significa que el navegador inició la descarga; si todavía "
        "EXISTE en el disco en esa ruta hay que verificarlo aparte revisando esa carpeta. "
        "Si NO está, no se puede saber desde este registro si fue movido, borrado o nunca llegó "
        "a guardarse — solo que el navegador lo intentó."
    ),
    "logins": (
        "La libreta de 'usuario y contraseña recordados' del navegador — lo mismo que aparece en "
        "chrome://settings/passwords. Por cada combinación sitio + usuario guardada hay una fila. "
        "Ej: una fila con sitio 'https://github.com' y usuario 'manuel' significa que en algún "
        "momento se guardó esa credencial para autocompletar al volver a entrar a GitHub. "
        "Si la columna 'Cifrado (no descifrable)' dice 'Sí', el password está protegido por "
        "Windows y la app no pudo leerlo — pero SABER en qué sitios había contraseñas guardadas "
        "ya es información útil (revela el catálogo de cuentas que pasaron por este navegador). "
        "La sola presencia de una credencial no implica que esa cuenta sea de la persona dueña "
        "del equipo — el navegador guarda lo que se le diga."
    ),
    "bookmarks": (
        "Los favoritos del navegador — las páginas que SÍ se guardaron a propósito haciendo "
        "'Agregar a favoritos' o ⭐. A diferencia del Historial (que se llena solo), aquí solo "
        "aparecen URLs que alguien guardó deliberadamente. "
        "Ej: una fila con nombre 'BBVA Banca' y URL 'https://www.bbva.com.ec/' en la carpeta "
        "'Bancos' indica que esa URL fue marcada como favorita. "
        "La columna 'Fecha en que se guardó el favorito' suele ser un dato más confiable que el "
        "historial: alguien tuvo que abrir el menú y guardar el favorito explícitamente."
    ),
    "autofill": (
        "Datos que el navegador 'aprendió' de los formularios web — lo que va llenando solo "
        "cuando uno empieza a escribir en un campo. "
        "Ej: si en algún momento se escribió 'manuel@ejemplo.com' en un campo de correo y se "
        "aceptó guardarlo, aparece una fila con campo='email', valor='manuel@ejemplo.com'. "
        "Cosas típicas que se guardan: correos, nombres, números de teléfono, direcciones "
        "postales, búsquedas previas en sitios. "
        "NO se guardan contraseñas aquí — esas viven en la hoja Logins."
    ),
    "extensions": (
        "Extensiones instaladas en el navegador — los 'add-ons' que se ven en chrome://extensions "
        "o about:addons en Firefox. Pueden ser inocuas (bloqueador de anuncios, traductor, "
        "lector PDF) o relevantes para revisar (VPN, proxy, billetera de criptomonedas, "
        "descargador de video, herramientas para limpiar historial). "
        "El 'ID de la extensión' es un código único — copiándolo en chrome.google.com/webstore "
        "o addons.mozilla.org se ve exactamente cuál extensión es. "
        "Ej: el ID 'cjpalhdlnbpafiamejdnhcphjbkeiagm' corresponde a uBlock Origin."
    ),
    "cache_entries": (
        "Caché del navegador: copias locales de cosas que el navegador descargó alguna vez "
        "(imágenes, scripts, partes de páginas) para no tener que volver a pedirlas en cada "
        "visita. Es lo que hace que las páginas que se visitan mucho carguen más rápido. "
        "Para análisis es un rastro INDIRECTO: si una URL aparece aquí significa que el "
        "navegador la abrió al menos una vez — aunque solo haya sido para cargar una imagen "
        "embebida — INCLUSO si esa URL no figura en el historial visible. "
        "Ej: si en el caché aparece 'twitter.com/...' pero en el historial no hay nada de "
        "Twitter, alguien pudo haber abierto la pestaña, mirado y cerrado sin que quede "
        "registrado en el historial."
    ),
    "web_storage": (
        "Espacios donde los sitios web guardan datos dentro del navegador. Aquí es donde las "
        "aplicaciones web modernas (WhatsApp Web, Discord, Telegram Web, Slack, Microsoft Teams) "
        "guardan los MENSAJES de chat para que aparezcan al volver a entrar al sitio sin tener "
        "que descargarlos otra vez. "
        "Ej: una fila con dominio 'https://web.whatsapp.com' y tipo 'IndexedDB' suele contener "
        "mensajes y contactos de WhatsApp Web. "
        "Cada fila: qué sitio, en qué tipo de almacén, qué guardó (clave + valor)."
    ),
    "open_tabs": (
        "Las pestañas que estaban abiertas en el navegador la última vez. "
        "Sesión activa = lo que estaba abierto JUSTO ahora; Sesión anterior = lo que estaba "
        "abierto antes de la última vez que se cerró el navegador. "
        "Ej: si la sesión activa tiene 5 pestañas abiertas en bancos y otra en correo, indica "
        "qué se estaba mirando al momento del análisis. "
        "Útil para reconstruir qué páginas se estaban consultando justo antes de cerrar o "
        "apagar el equipo."
    ),
    "permissions": (
        "Permisos que se les dieron a los sitios web — la misma lista que aparece en "
        "chrome://settings/content. Por cada decisión (permitir o bloquear) hay una fila. "
        "Ej: 'meet.google.com → camera → Permitido' significa que a Google Meet se le dio "
        "acceso a la cámara web. 'facebook.com → notifications → Bloqueado' significa que se "
        "bloqueó que Facebook mande notificaciones de escritorio. "
        "Esta hoja muestra QUÉ se autorizó, no si efectivamente se usó."
    ),
}


# Leyenda objetiva del campo visit_type. Cada descripción documenta el
# mecanismo que generó la entrada según la base de datos del navegador,
# sin atribuir intencionalidad al usuario (el campo no diferencia entre
# acción humana directa, scripts, redirecciones automáticas o pruebas).
#
# Solo incluimos aquí los códigos comunes a Chromium + Firefox que un
# revisor encuentra habitualmente. Los específicos de un navegador en
# particular (bookmark, embed, framed_link) o los muy poco frecuentes
# (manual_subframe, auto_toplevel, keyword, keyword_generated) quedan
# sin leyenda; siguen apareciendo en la columna 'visit_type' tal cual
# si llegan a presentarse.
_VISIT_TYPE_LEGEND: dict[str, str] = {
    "typed":
        "La URL se ingresó directamente en la barra de direcciones del navegador (la barra de "
        "arriba, donde dice https://). Aplica tanto si se escribió letra por letra como si se "
        "pegó con copy/paste. Ej: alguien escribió 'banco.com' arriba y dio Enter.",
    "link":
        "Se llegó haciendo click en un enlace que estaba en OTRA página. Ej: estando en Google "
        "leyendo resultados de búsqueda, se hizo click en uno de los enlaces de la lista — la "
        "página de destino aparece marcada así.",
    "auto_bookmark":
        "Se llegó abriendo un favorito guardado del navegador (la estrellita ⭐). "
        "Ej: si Facebook está en favoritos y se le da click ahí, la entrada queda marcada así.",
    "auto_subframe":
        "La URL se cargó SOLA dentro de un recuadrito pequeño embebido en otra página — sin "
        "acción del usuario. Ej: un anuncio que aparece en un blog, un widget de Twitter "
        "embebido en una noticia, un contador de visitas oculto. La URL del recuadrito embebido "
        "se registra aunque nadie haya interactuado con ella.",
    "generated":
        "La URL fue armada por el AUTOCOMPLETADO del navegador. Ej: si se empieza a escribir "
        "'fac' en la barra y aparece la sugerencia 'facebook.com/manuel' que se acepta dando "
        "Enter, la URL final que se abrió queda como 'generated' (no como 'typed', porque no se "
        "escribió completa).",
    "form_submit":
        "La URL es la página a la que se llegó DESPUÉS de enviar un formulario. Ej: en un login, "
        "tras poner usuario+contraseña y darle 'Iniciar sesión', la página de bienvenida que "
        "carga el navegador queda marcada así. También aplica para envíos de búsqueda, "
        "registros, contactos, etc.",
    "reload":
        "Recarga de la misma página — apretar F5, Ctrl+R, el botón de recargar del navegador, "
        "o que un script de la propia página la recargue automáticamente.",
    "redirect_permanent":
        "Redirección automática que el servidor del sitio ordenó con código HTTP 301 ('movida "
        "para siempre'). Ej: el sitio se mudó de dominio (de 'oldname.com' a 'newname.com'); "
        "cualquiera que entre al viejo es enviado automáticamente al nuevo.",
    "redirect_temporary":
        "Redirección automática del servidor con código HTTP 302/303/307 ('movida por ahora'). "
        "Muy común en flujos de login: tras autenticarse el servidor 'rebota' al navegador a la "
        "página principal del sitio. También aparece con URLs cortas tipo 'bit.ly/abc123' que "
        "redirigen al destino final.",
    "download":
        "La URL terminó disparando una descarga de archivo (PDF, ZIP, instalador, video, etc.). "
        "El detalle completo del archivo descargado aparece en la hoja 'Downloads'.",
    "carved":
        "Esta fila NO estaba viva en la base de datos del navegador en el momento de la "
        "extracción. La app la rescató de espacio no asignado dentro del archivo del historial. "
        "Ej: si alguien borra el historial desde el menú del navegador, las URLs no desaparecen "
        "del archivo de inmediato — quedan en huecos internos hasta que algo nuevo las "
        "sobreescriba. Las filas marcadas 'carved' son exactamente esos restos rescatados. "
        "No se puede determinar QUIÉN ni CUÁNDO las borró — solo que en algún momento se "
        "marcaron como eliminadas y la app las pudo recuperar.",
}


# Per-column tooltips so a non-technical reader gets context when they
# hover or check the second header row.
_FIELD_HINTS: dict[str, dict[str, str]] = {
    "history": {
        "url": "URL completa de la página",
        "title": "Título mostrado en la pestaña",
        "visit_count": "Número total de visitas registradas",
        "typed_count": "Contador que lleva el navegador de visitas con visit_type='typed'",
        "last_visit": "Fecha y hora de la última visita (UTC-5)",
        "visit_type": "Cómo se llegó a la página: typed=escrita, link=clic, bookmark=desde favorito, carved=recuperada de borrado",
        "deleted": "True si la entrada fue recuperada de espacio borrado",
        "from_visit_url": "Página de la que se vino (referrer)",
        "category": "Clasificación automática (banking, social, im…)",
    },
    "cookies": {
        "host": "Sitio que dejó la cookie (clave del 'a qué sitio se conectó')",
        "name": "Nombre interno de la cookie",
        "value": "Contenido (a menudo cifrado o token opaco)",
        "expires": "Cuándo expira la cookie",
        "created": "Cuándo el sitio creó la cookie en este equipo",
        "last_access": "Última vez que el navegador la envió al sitio",
        "secure": "Solo viaja por HTTPS",
        "http_only": "JavaScript no puede leerla (anti-robo)",
        "same_site": "Política contra peticiones desde otros dominios",
        "encrypted": "True si no se pudo descifrar el valor (común en imagen sin DPAPI)",
    },
    "downloads": {
        "url": "URL de origen del archivo",
        "target_path": "Ruta local donde se guardó (si todavía existe = evidencia directa)",
        "referrer": "Página desde donde se inició la descarga",
        "mime_type": "Tipo MIME (image/jpeg, application/pdf…)",
        "total_bytes": "Tamaño total en MB (binario, 1 MB = 1 048 576 bytes)",
        "received_bytes": "MB realmente descargados (binario, 1 MB = 1 048 576 bytes)",
        "state": "complete=ok, cancelled=cancelado, interrupted=cortado",
        "start_time": "Cuándo empezó la descarga",
        "end_time": "Cuándo terminó",
    },
    "logins": {
        "origin_url": "Sitio donde se guardó la credencial",
        "action_url": "URL del formulario de login",
        "username": "Usuario guardado",
        "password": "Contraseña descifrada (vacío si encrypted=True)",
        "date_created": "Marca temporal del primer registro de esta credencial en el navegador",
        "date_last_used": "Última vez que se usó el autocompletado",
        "times_used": "Número de veces que se rellenó automáticamente",
        "encrypted": "True si el password no pudo descifrarse",
    },
    "bookmarks": {
        "folder": "Carpeta dentro de los favoritos",
        "name": "Nombre del favorito tal como aparece registrado",
        "url": "URL guardada",
        "date_added": "Cuándo lo guardó",
        "date_modified": "Última edición del favorito",
    },
    "autofill": {
        "field_name": "Nombre del campo del formulario (email, telefono, address…)",
        "value": "Valor capturado por el navegador durante el llenado del formulario",
        "count": "Veces que ese valor se usó",
        "first_used": "Primera vez que lo escribió",
        "last_used": "Última vez que lo reutilizó",
    },
    "extensions": {
        "extension_id": "ID único (buscable en Chrome Web Store / AMO)",
        "name": "Nombre visible de la extensión",
        "version": "Versión instalada",
        "description": "Lo que dice hacer",
        "enabled": "Si estaba activa o desinstalada/desactivada",
        "install_path": "Carpeta local donde vive",
    },
    "cache_entries": {
        "url": "URL del recurso cacheado",
        "mime_type": "Tipo de contenido",
        "size": "Tamaño en MB (binario, 1 MB = 1 048 576 bytes)",
        "fetched_at": "Cuándo el navegador la pidió por primera vez",
        "last_used": "Última vez que la sirvió desde caché",
        "status_code": "Código HTTP que respondió el servidor",
        "source": "Origen del archivo cacheado",
    },
    "web_storage": {
        "origin": "Sitio web dueño del dato",
        "kind": "localstorage / sessionstorage / indexeddb",
        "key": "Clave (nombre del dato)",
        "value": "Contenido (puede ser texto, JSON, blob…)",
        "last_modified": "Última modificación del dato",
        "source": "Archivo del que se extrajo",
    },
    "open_tabs": {
        "session": "current=actual, last=sesión anterior",
        "window_idx": "Índice de la ventana del navegador",
        "tab_idx": "Posición de la pestaña dentro de la ventana",
        "url": "URL abierta",
        "title": "Título de la pestaña",
        "last_active": "Última vez que estuvo activa",
        "pinned": "True si era una pestaña fijada",
    },
    "permissions": {
        "origin": "Sitio al que se le concedió/denegó permiso",
        "permission": "Qué permiso (notifications, geolocation, camera, microphone…)",
        "setting": "allow=permitido, block=bloqueado, ask=preguntar cada vez",
        "last_modified": "Cuándo se cambió el permiso",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# openpyxl mirrors Excel's own restriction: cells must not carry control
# characters \x00-\x08, \x0B-\x0C, \x0E-\x1F. They sneak in via cookie
# values, LocalStorage blobs, IM message bodies and similar binary-leaning
# fields — and they crash the workbook with ``IllegalCharacterError`` at
# save time. We strip them here so the export never fails on a single
# tainted byte.
import re as _re
_ILLEGAL_XLSX_CHARS = _re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def _clean_for_excel(value):
    """Make *value* safe to write into an openpyxl cell.

    - ``bytes`` get decoded with replacement so we don't lose the row.
    - ``str`` has its illegal control characters mapped to ``\\ufffd``
      (the standard Unicode replacement char, visible in Excel as a
      diamond-question mark — the analyst can spot tampered cells).
    - Everything else (int, float, bool, datetime, None) passes through.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str) and _ILLEGAL_XLSX_CHARS.search(value):
        return _ILLEGAL_XLSX_CHARS.sub("�", value)
    return value


# Columns we never want to see in the export. ``deleted`` and ``category``
# are internal markers — the deleted flag is conveyed by the dedicated
# carved-row banner / visit_type='carved' on history, and category is an
# automated tag that doesn't add value to the analyst's report.
_HIDDEN_COLUMNS: set[str] = {"deleted", "category"}

# Byte-counting columns we want shown as binary megabytes (MiB) instead
# of raw bytes. Mapping value is the new column name shown in the sheet.
# 1 MB = 1024 KB = 1 048 576 bytes (the user explicitly asked for the
# binary form, not the decimal SI MB).
_BYTES_TO_MB_COLUMNS: dict[str, str] = {
    "total_bytes": "total_mb",
    "received_bytes": "received_mb",
    "size": "size_mb",
}

_BYTES_PER_MB = 1024 * 1024


def _visible_fieldname(name: str) -> Optional[str]:
    """Return the *display* column name for *name*, or ``None`` if hidden."""
    if name in _HIDDEN_COLUMNS:
        return None
    return _BYTES_TO_MB_COLUMNS.get(name, name)


def _value_for_export(name: str, value):
    """Apply per-column transformations before the value reaches the cell.

    For byte columns the integer count is divided by ``1024*1024`` and
    rounded to 4 decimals so 1 KB shows up as ``0.001`` MB rather than a
    long floating-point number. ``None`` / non-numeric falls through
    untouched.
    """
    if name in _BYTES_TO_MB_COLUMNS:
        if value is None or value == "":
            return value
        try:
            return round(float(value) / _BYTES_PER_MB, 4)
        except (TypeError, ValueError):
            return value
    return value


def _truncate(value, limit: int = 32767):
    """Sanitize + tz-convert + length-clamp any value going into a cell.

    Three jobs in one helper so every ``ws.cell(...value=...)`` call is
    covered by going through here:

    1. :func:`_format_dt` — convert any datetime (object or ISO string)
       to a naive datetime in UTC-5 so Excel shows local time.
    2. :func:`_clean_for_excel` — strip control characters cookie / IDB /
       IM payloads routinely carry, which otherwise crash
       ``Workbook.save`` with ``IllegalCharacterError``.
    3. Length clamp to Excel's 32 767-char cell limit.
    """
    value = _format_dt(value)
    value = _clean_for_excel(value)
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 3] + "…"
    return value


def _format_dt(value):
    """Render *value* as a naive datetime in :data:`REPORT_TZ` (UTC-5).

    Accepts both ``datetime`` objects (aware or naive — naive assumed
    UTC, since all extractors emit UTC) and ISO-8601 strings (which is
    what :meth:`ArtifactBase.to_dict` produces). Anything else passes
    through unchanged so we don't break URL / text columns that happen
    to live in the same row.

    The returned datetime is naive because openpyxl needs naive
    datetimes to format them as date cells; the tz info is stripped
    after the conversion to UTC-5 happened.
    """
    if value is None or value == "":
        return value
    dt: Optional[datetime] = None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        # Cheap pre-check: ISO datetimes start with YYYY-MM-DD. Anything
        # else (URLs, plain text, etc.) skips the parse cost.
        if len(value) >= 10 and value[4:5] == "-" and value[7:8] == "-":
            stripped = value.rstrip("Z")
            try:
                dt = datetime.fromisoformat(stripped)
            except (TypeError, ValueError):
                return value
            if value.endswith("Z") and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    if dt is None:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(REPORT_TZ)
    return dt.replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class XlsxExporter(ExporterBase):
    """Excel workbook with one sheet per artifact + an interpretation sheet.

    Optionally pulls additional forensic data tables (search terms,
    accounts, IM messages, JWT tokens, OS artifacts, IOCs, findings,
    chain-of-custody, analyst notes, domain enrichment) directly from
    the :class:`SessionStore` when one is provided — see the *store*
    and *extras* kwargs.
    """

    extension = ".xlsx"

    def export(
        self,
        bundles: Iterable[ProfileBundle],
        out_path: str | Path,
        kinds: Iterable[str] = ARTIFACT_KINDS,
        store=None,
        extras: Iterable[str] = (),
        profile_ids: Iterable[int] | None = None,
    ) -> Path:
        """Write the XLSX workbook to *out_path*.

        ``profile_ids`` filters the extra-table sheets (search_terms,
        accounts, …) to only rows belonging to those profile IDs. When
        ``None`` every row in the store is included. ``bundles`` is
        already filtered by the caller.
        """
        if not _HAS_OPENPYXL:
            raise RuntimeError(
                "openpyxl is not installed — run `pip install openpyxl` to enable XLSX export."
            )
        out = Path(out_path)
        if out.is_dir() or out.suffix.lower() != ".xlsx":
            out = (out / "webforensics.xlsx") if out.is_dir() else out.with_suffix(".xlsx")
        out.parent.mkdir(parents=True, exist_ok=True)

        kinds_list = [k for k in kinds if k in ARTIFACT_KINDS]
        extras_list = [e for e in extras if e in EXTRA_TABLES]
        bundles_list = list(bundles)
        pid_filter = list(profile_ids) if profile_ids is not None else None

        wb = Workbook()
        wb.remove(wb.active)

        self._write_overview(wb, bundles_list, kinds_list, extras_list, store)
        self._write_profiles(wb, bundles_list)

        for kind in kinds_list:
            self._write_artifact_sheet(wb, kind, bundles_list)

        # Forensic extras (only when the caller passed a store).
        if store is not None and extras_list:
            for table in extras_list:
                self._write_extra_sheet(wb, store, table, pid_filter)

        self._write_errors(wb, bundles_list)

        wb.save(out)
        return out

    # --- Sheets -----------------------------------------------------------

    def _write_overview(
        self,
        wb,
        bundles: list[ProfileBundle],
        kinds: list[str],
        extras: list[str] = (),
        store=None,
    ) -> None:
        ws = wb.create_sheet("Resumen")
        title_font = Font(name="Calibri", size=18, bold=True, color="1F4E78")
        section_font = Font(name="Calibri", size=12, bold=True, color="1F4E78")
        body_font = Font(name="Calibri", size=11)
        wrap = Alignment(wrap_text=True, vertical="top")

        ws["A1"] = "WebForensics — reporte de análisis"
        ws["A1"].font = title_font
        ws.merge_cells("A1:F1")

        ws["A3"] = (
            "Reporte de extracción y análisis de perfiles de navegador. "
            "Cada hoja contiene un tipo de artefacto independiente. "
            "La leyenda al final de esta hoja documenta el significado de cada uno. "
            f"Todas las fechas y horas están en hora local {REPORT_TZ_LABEL}."
        )
        ws["A3"].font = body_font
        ws["A3"].alignment = wrap
        ws.merge_cells("A3:F4")

        # Leyenda de artefactos
        row = 6
        ws.cell(row=row, column=1, value="Leyenda de artefactos")
        ws.cell(row=row, column=1).font = section_font
        row += 1
        for kind in kinds:
            es = _ARTIFACT_INTERPRETATIONS.get(kind, "")
            ws.cell(row=row, column=1, value=kind).font = Font(bold=True)
            ws.cell(row=row, column=2, value=es).alignment = wrap
            ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=6)
            row += 2

        # Explain the extras too if any were selected.
        if extras:
            row += 1
            ws.cell(row=row, column=1, value="Datos forenses adicionales").font = section_font
            row += 1
            for extra in extras:
                es = EXTRA_INTERPRETATIONS.get(extra, "")
                ws.cell(row=row, column=1, value=EXTRA_TABLE_HUMAN_NAMES.get(extra, extra)).font = Font(bold=True)
                ws.cell(row=row, column=2, value=es).alignment = wrap
                ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=6)
                row += 2

        # Column widths
        widths = (16, 28, 14, 14, 14, 14)
        for idx, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = w
        ws.row_dimensions[3].height = 60
        ws.freeze_panes = "A7"

    def _write_profiles(self, wb, bundles: list[ProfileBundle]) -> None:
        ws = wb.create_sheet("Perfiles")
        headers = ("Navegador", "Perfil", "Ruta", "Total artefactos", "Errores")
        self._write_header_row(ws, headers)
        for row_idx, bundle in enumerate(bundles, start=2):
            total = sum(len(bundle.get(k)) for k in ARTIFACT_KINDS)
            ws.cell(row=row_idx, column=1, value=bundle.browser)
            ws.cell(row=row_idx, column=2, value=bundle.profile)
            ws.cell(row=row_idx, column=3, value=_truncate(bundle.path))
            ws.cell(row=row_idx, column=4, value=total)
            ws.cell(row=row_idx, column=5, value="; ".join(bundle.errors[:5]))
        self._finalize(ws, headers, max(2, len(bundles) + 1))

    def _write_artifact_sheet(
        self,
        wb,
        kind: str,
        bundles: list[ProfileBundle],
    ) -> None:
        # Excel sheet names: 31 chars max, no certain chars.
        sheet_name = kind.replace("_", " ").title()[:31]
        ws = wb.create_sheet(sheet_name)

        # First: a 2-row banner with the friendly description. History
        # tacks on the visit_type legend so the analyst doesn't have to
        # cross-reference what each code means.
        banner = _ARTIFACT_INTERPRETATIONS.get(kind, "")
        if kind == "history":
            legend_lines = ["", "Tipos de visita (columna visit_type):"]
            for code, meaning in _VISIT_TYPE_LEGEND.items():
                legend_lines.append(f"  • {code}: {meaning}")
            banner = banner + "\n" + "\n".join(legend_lines)
        ws["A1"] = banner
        ws["A1"].font = Font(italic=True, color="444444")
        ws["A1"].alignment = Alignment(wrap_text=True, vertical="top")
        # Make the row tall enough to show the multi-line legend for History.
        ws.row_dimensions[1].height = 320 if kind == "history" else 48

        rows: list[dict] = []
        for bundle in bundles:
            for item in bundle.get(kind):
                rows.append(item.to_dict())

        if not rows:
            ws["A3"] = "(sin datos)"
            ws.merge_cells("A1:H1")
            return

        # Union of all keys, stable order, hidden columns excluded.
        fieldnames: list[str] = []
        for r in rows:
            for k in r:
                if k not in fieldnames and _visible_fieldname(k) is not None:
                    fieldnames.append(k)
        display_names = [_visible_fieldname(k) for k in fieldnames]

        # Merge banner across all columns.
        last_col_letter = get_column_letter(len(fieldnames))
        ws.merge_cells(f"A1:{last_col_letter}1")

        # Header row at row 3, data starts at row 4.
        header_row = 3
        self._write_header_row(ws, display_names, row=header_row)

        # Column tooltips (Excel comments) using the field hints. The
        # hint table is keyed by the *raw* field name, so we look up
        # using ``name`` even when the display column is renamed.
        hints = _FIELD_HINTS.get(kind, {})
        from openpyxl.comments import Comment
        for col_idx, name in enumerate(fieldnames, start=1):
            hint = hints.get(name)
            if hint:
                cell = ws.cell(row=header_row, column=col_idx)
                cell.comment = Comment(hint, "WebForensics")

        for r_idx, row in enumerate(rows, start=header_row + 1):
            for c_idx, name in enumerate(fieldnames, start=1):
                value = _value_for_export(name, row.get(name))
                # _truncate runs _format_dt + _clean_for_excel internally —
                # do NOT call _format_dt here too or naive datetimes get
                # converted twice and shift by another -5 hours.
                ws.cell(row=r_idx, column=c_idx, value=_truncate(value))

        self._finalize(ws, display_names, header_row + len(rows), header_row=header_row)

    def _write_extra_sheet(
        self,
        wb,
        store,
        table: str,
        profile_ids: list[int] | None = None,
    ) -> None:
        """Dump an arbitrary SessionStore table to its own sheet.

        Uses a SELECT * to stay schema-agnostic. When *profile_ids* is
        provided AND the target table has a ``profile_id`` column, the
        query is filtered to those profiles so per-profile exports stay
        consistent across all sheets.
        """
        human = EXTRA_TABLE_HUMAN_NAMES.get(table, table)
        sheet_name = human[:31]
        ws = wb.create_sheet(sheet_name)

        es = EXTRA_INTERPRETATIONS.get(table, "")
        ws["A1"] = es
        ws["A1"].font = Font(italic=True, color="444444")
        ws["A1"].alignment = Alignment(wrap_text=True, vertical="top")
        ws.row_dimensions[1].height = 56

        try:
            conn = store.connection()
            # Detect whether this table carries a profile_id we can filter on.
            table_cols = {
                r[1] for r in conn.execute(f"PRAGMA table_info({table})")
            }
            sql = f"SELECT * FROM {table}"
            params: tuple = ()
            if profile_ids and "profile_id" in table_cols:
                placeholders = ",".join("?" for _ in profile_ids)
                sql += f" WHERE profile_id IN ({placeholders})"
                params = tuple(profile_ids)
            cursor = conn.execute(sql, params)
            columns = [d[0] for d in cursor.description] if cursor.description else []
            rows = cursor.fetchall()
        except Exception as exc:  # noqa: BLE001
            ws["A2"] = f"(error leyendo tabla: {exc})"
            return

        if not columns:
            ws["A3"] = "(sin columnas)"
            return

        # Apply the same hidden-column + bytes-to-MB transforms the
        # per-artifact sheets use, so behaviour is consistent across the
        # whole workbook (e.g. source_files.size → size_mb).
        columns = [c for c in columns if _visible_fieldname(c) is not None]
        display_columns = [_visible_fieldname(c) for c in columns]

        if not rows:
            last_col_letter = get_column_letter(max(1, len(columns)))
            ws.merge_cells(f"A1:{last_col_letter}1")
            ws["A3"] = "(sin datos)"
            return

        last_col_letter = get_column_letter(len(columns))
        ws.merge_cells(f"A1:{last_col_letter}1")

        header_row = 3
        self._write_header_row(ws, display_columns, row=header_row)
        for r_idx, row in enumerate(rows, start=header_row + 1):
            for c_idx, col in enumerate(columns, start=1):
                value = _value_for_export(col, row[col])
                # _truncate handles tz conversion + char sanitisation in one shot.
                ws.cell(row=r_idx, column=c_idx, value=_truncate(value))
        self._finalize(ws, display_columns, header_row + len(rows), header_row=header_row)

    def _write_errors(self, wb, bundles: list[ProfileBundle]) -> None:
        # Collect all errors with their profile context.
        errors: list[tuple[str, str, str]] = []
        for bundle in bundles:
            for err in bundle.errors:
                errors.append((bundle.browser, bundle.profile, err))
        if not errors:
            return
        ws = wb.create_sheet("Errores")
        ws["A1"] = (
            "Mensajes informativos y de error del proceso de extracción. La mayoría son notas "
            "(p. ej. 'image source = X.E01' o 'carved N deleted history records'), no fallos críticos."
        )
        ws["A1"].alignment = Alignment(wrap_text=True, vertical="top")
        ws["A1"].font = Font(italic=True, color="444444")
        ws.row_dimensions[1].height = 36
        headers = ("Navegador", "Perfil", "Mensaje")
        ws.merge_cells("A1:C1")
        self._write_header_row(ws, headers, row=3)
        for idx, (br, prof, err) in enumerate(errors, start=4):
            ws.cell(row=idx, column=1, value=br)
            ws.cell(row=idx, column=2, value=prof)
            ws.cell(row=idx, column=3, value=_truncate(err))
        self._finalize(ws, headers, 3 + len(errors), header_row=3)


    # --- Styling helpers ---------------------------------------------

    def _write_header_row(self, ws, headers: Iterable[str], row: int = 1) -> None:
        fill = PatternFill("solid", fgColor="1F4E78")
        font = Font(bold=True, color="FFFFFF")
        thin = Side(border_style="thin", color="DDDDDD")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)
        for col_idx, name in enumerate(headers, start=1):
            cell = ws.cell(row=row, column=col_idx, value=name)
            cell.fill = fill
            cell.font = font
            cell.border = border

    def _finalize(
        self,
        ws,
        headers,
        last_row: int,
        header_row: int = 1,
    ) -> None:
        n_cols = len(list(headers))
        if n_cols == 0:
            return
        # Auto-size columns based on header + sample of values.
        for col_idx in range(1, n_cols + 1):
            max_len = 0
            letter = get_column_letter(col_idx)
            for r in range(header_row, min(header_row + 200, last_row + 1)):
                v = ws.cell(row=r, column=col_idx).value
                if v is None:
                    continue
                s = str(v)
                if len(s) > max_len:
                    max_len = len(s)
            ws.column_dimensions[letter].width = min(max(12, max_len + 2), 60)
        # Freeze the header so data scrolls under it.
        ws.freeze_panes = ws.cell(row=header_row + 1, column=1).coordinate
        # AutoFilter on the data range.
        if last_row > header_row:
            end_letter = get_column_letter(n_cols)
            ws.auto_filter.ref = f"A{header_row}:{end_letter}{last_row}"
