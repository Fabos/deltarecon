#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="0.16.7"
MONTOYA_VERSION="2026.7"
DEPS="$HERE/.deps"
CLASSES="$HERE/build/classes/java/main"
LIBS="$HERE/build/libs"
MONTOYA_JAR="$DEPS/montoya-api-$MONTOYA_VERSION.jar"

mkdir -p "$DEPS" "$CLASSES" "$LIBS"

if ! command -v java >/dev/null 2>&1 || ! command -v javac >/dev/null 2>&1; then
  echo "[ERROR] Java/JDK no está instalado. Se requiere JDK 21 o superior." >&2
  exit 1
fi

JAVA_MAJOR="$(javac -version 2>&1 | awk '{print $2}' | cut -d. -f1)"
if [ "$JAVA_MAJOR" -lt 21 ]; then
  echo "[ERROR] javac $JAVA_MAJOR detectado. Se requiere JDK 21 o superior." >&2
  exit 1
fi

if [ ! -s "$MONTOYA_JAR" ]; then
  URL="https://repo.maven.apache.org/maven2/net/portswigger/burp/extensions/montoya-api/$MONTOYA_VERSION/montoya-api-$MONTOYA_VERSION.jar"
  echo "[INFO] Descargando Montoya API $MONTOYA_VERSION..."
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 15 "$URL" -o "$MONTOYA_JAR"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$MONTOYA_JAR" "$URL"
  else
    echo "[ERROR] Necesitas curl o wget para descargar Montoya API una sola vez." >&2
    exit 1
  fi
fi

rm -rf "$CLASSES"
mkdir -p "$CLASSES" "$LIBS"
mapfile -t SOURCES < <(find "$HERE/src/main/java" -type f -name '*.java' -print)
if [ "${#SOURCES[@]}" -eq 0 ]; then
  echo "[ERROR] No se encontraron fuentes Java." >&2
  exit 1
fi

echo "[INFO] Compilando Negro Burp Bridge para Java 21..."
javac --release 21 -encoding UTF-8 -cp "$MONTOYA_JAR" -d "$CLASSES" "${SOURCES[@]}"

MANIFEST="$HERE/build/manifest.mf"
cat > "$MANIFEST" <<EOF
Manifest-Version: 1.0
Implementation-Title: Negro Burp Bridge
Implementation-Version: $VERSION

EOF

OUT="$LIBS/negro-burp-bridge-$VERSION.jar"
jar --create --file "$OUT" --manifest "$MANIFEST" -C "$CLASSES" .
echo "[OK] Extensión compilada: $OUT"
