import streamlit as st
from datetime import datetime, timedelta
from PIL import Image
import os
import base64
from io import BytesIO
import uuid
import pandas as pd
import paramiko
import csv
from io import StringIO
import tempfile
import pytz
import re
import json
import threading
from functools import wraps, lru_cache
import hashlib
import time
import atexit
import socket
import signal


# ====================
# CONCURRENCY MANAGER
# ====================
class ConcurrencyManager:
    _instance = None
    _locks = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConcurrencyManager, cls).__new__(cls)
        return cls._instance
    
    def get_lock(self, resource_name):
        if resource_name not in self._locks:
            self._locks[resource_name] = threading.Lock()
        return self._locks[resource_name]

def synchronized(resource_name):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            manager = ConcurrencyManager()
            lock = manager.get_lock(resource_name)
            with lock:
                return func(*args, **kwargs)
        return wrapper
    return decorator

def retry(tries=3, delay=1, backoff=2):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if "file already exists" in str(e).lower() or "lock" in str(e).lower() or "timeout" in str(e).lower():
                        time.sleep(mdelay)
                        mtries -= 1
                        mdelay *= backoff
                    else:
                        raise e
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ====================
# CONFIGURACIÓN INICIAL (COMPLETA Y CORREGIDA)
# ====================
class Config:
    def __init__(self):
        # SFTP Configuration
        self.REMOTE = {
            'HOST': st.secrets["remote_host"],
            'USER': st.secrets["remote_user"],
            'PASSWORD': st.secrets["remote_password"],
            'PORT': st.secrets["remote_port"],
            'DIR': st.secrets["remote_dir"],
            'TIMEOUT_SECONDS': 30
        }

        # File Configuration
        self.FILES = {
            "enfermeras": st.secrets["file_enfermeras2"],
            "claves": st.secrets["file_creacion_enfermeras2"],
            "pacientes": st.secrets["file_pacientes2"]
        }

        # App Configuration
        self.SUPERVISOR_MODE = st.secrets.get("supervisor_mode", True)
        self.DEBUG_MODE = st.secrets.get("debug_mode", False)

        # Diagnósticos disponibles
        self.DIAGNOSTICOS = [
            "Infarto agudo de miocardio", "Angina de pecho", "Insuficiencia cardíaca",
            "Arritmia cardíaca", "Fibrilación auricular", "Taquicardia ventricular",
            "Bradicardia", "Cardiopatía isquémica", "Miocardiopatía dilatada",
            "Miocardiopatía hipertrófica", "Valvulopatía cardíaca", "Endocarditis",
            "Pericarditis", "Enfermedad arterial coronaria", "Hipertensión arterial",
            "Cardiopatía congénita", "Shock cardiogénico", "Edema agudo de pulmón",
            "Embolia pulmonar", "Disección aórtica", "Aneurisma aórtico",
            "Enfermedad vascular periférica", "Síncope", "Paro cardiorrespiratorio",
            "Marcapasos implantado", "Stent coronario", "By-pass coronario",
            "Trasplante cardíaco", "Amiloidosis cardíaca", "Tumor cardíaco"
        ]
        
        # Configuración de camas por servicio
        self.CAMAS_POR_SERVICIO = {
            "UNIDAD-CORONARIA": {
                "total_camas": 22,
                "rango_inicio": 201,
                "rango_fin": 222
            }
        }

CONFIG = Config()

# ====================
# CONNECTION POOL MANAGER (MEJORADO) - INSTANCIAR PRIMERO
# ====================
class ConnectionPool:
    _instance = None
    _pool = {}
    _lock = threading.Lock()
    _max_connections_per_host = 5
    _connection_timeout = 180  # 3 minutos

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConnectionPool, cls).__new__(cls)
        return cls._instance

    def get_connection(self, host, port, username, password):
        """Obtiene una conexión del pool o crea una nueva"""
        key = f"{host}:{port}:{username}"

        with self._lock:
            self._clean_expired_connections()

            # Buscar conexión disponible
            if key in self._pool:
                for i, (conn, last_used, in_use) in enumerate(self._pool[key]):
                    if not in_use and self._is_connection_usable(conn):
                        self._pool[key][i] = (conn, time.time(), True)
                        if CONFIG.DEBUG_MODE:
                            st.info(f"✓ Conexión reutilizada del pool: {key}")
                        return conn

            # Crear nueva conexión si no hay máximo
            if key not in self._pool:
                self._pool[key] = []

            if len(self._pool[key]) < self._max_connections_per_host:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # Configurar timeout de conexión
                    ssh.connect(
                        hostname=host,
                        port=int(port),
                        username=username,
                        password=password,
                        timeout=CONFIG.REMOTE['TIMEOUT_SECONDS'],
                        banner_timeout=20,
                        auth_timeout=20
                    )

                    # Verificar que la conexión sea usable
                    if self._is_connection_usable(ssh):
                        self._pool[key].append((ssh, time.time(), True))
                        if CONFIG.DEBUG_MODE:
                            st.info(f"✓ Nueva conexión creada: {key}")
                        return ssh
                    else:
                        try:
                            ssh.close()
                        except:
                            pass
                        return None

                except paramiko.AuthenticationException:
                    st.error("Error de autenticación SSH")
                    return None
                except paramiko.SSHException as e:
                    st.error(f"Error SSH: {str(e)}")
                    return None
                except socket.timeout:
                    st.error("Timeout de conexión SSH")
                    return None
                except Exception as e:
                    st.error(f"Error creando conexión: {str(e)}")
                    if CONFIG.DEBUG_MODE:
                        import traceback
                        st.error(f"Traceback: {traceback.format_exc()}")
                    return None
            else:
                # Esperar por conexión disponible
                wait_start = time.time()
                while time.time() - wait_start < 10:
                    for i, (conn, last_used, in_use) in enumerate(self._pool[key]):
                        if not in_use and self._is_connection_usable(conn):
                            self._pool[key][i] = (conn, time.time(), True)
                            if CONFIG.DEBUG_MODE:
                                st.info(f"✓ Conexión obtenida después de espera: {key}")
                            return conn
                    time.sleep(0.1)
                st.error("Timeout esperando conexión disponible en el pool")
                return None

    def return_connection(self, ssh_connection):
        """Devuelve una conexión al pool marcándola como disponible"""
        key = None
        for pool_key, connections in self._pool.items():
            for i, (conn, last_used, in_use) in enumerate(connections):
                if conn == ssh_connection:
                    key = pool_key
                    self._pool[key][i] = (conn, time.time(), False)
                    if CONFIG.DEBUG_MODE:
                        st.info(f"✓ Conexión devuelta al pool: {key}")
                    return True
        return False

    def _is_connection_usable(self, ssh_connection):
        """Verifica si una conexión es usable"""
        try:
            if ssh_connection is None:
                return False

            transport = ssh_connection.get_transport()
            if transport is None:
                return False

            return transport.is_active() and transport.is_authenticated()
        except:
            return False

    def _clean_expired_connections(self):
        """Limpia conexiones vencidas del pool"""
        current_time = time.time()
        for key in list(self._pool.keys()):
            # Filtrar conexiones válidas
            valid_connections = []
            for conn, last_used, in_use in self._pool[key]:
                if (self._is_connection_usable(conn) and
                    current_time - last_used < self._connection_timeout):
                    valid_connections.append((conn, last_used, in_use))
                else:
                    # Cerrar conexión expirada
                    try:
                        conn.close()
                    except:
                        pass

            self._pool[key] = valid_connections

            # Eliminar entrada si no hay conexiones
            if not self._pool[key]:
                del self._pool[key]
                if CONFIG.DEBUG_MODE:
                    st.info(f"✓ Pool entry removed: {key}")

    def close_all_connections(self):
        """Cierra todas las conexiones del pool"""
        with self._lock:
            for key in list(self._pool.keys()):
                for conn, last_used, in_use in self._pool[key]:
                    try:
                        conn.close()
                    except:
                        pass
                del self._pool[key]
            if CONFIG.DEBUG_MODE:
                st.info("✓ Todas las conexiones del pool cerradas")

    def get_pool_status(self):
        """Retorna el estado actual del pool para debugging"""
        with self._lock:
            status = {}
            for key, connections in self._pool.items():
                status[key] = {
                    'total_connections': len(connections),
                    'in_use': sum(1 for _, _, in_use in connections if in_use),
                    'available': sum(1 for _, _, in_use in connections if not in_use),
                    'usable': sum(1 for conn, _, _ in connections if self._is_connection_usable(conn))
                }
            return status

# ====================
# INSTANCIAR EL POOL DE CONEXIONES GLOBALMENTE
# ====================
CONNECTION_POOL = ConnectionPool()

# ==================
# FUNCIONES SSH/SFTP (OPTIMIZADAS CON TIMEOUTS)
# ==================
class SSHManager:
    @staticmethod
    @retry(tries=3, delay=1, backoff=2)
    def get_connection():
        """Establece conexión SSH usando el pool con reintentos"""
        try:
            ssh = CONNECTION_POOL.get_connection(
                CONFIG.REMOTE['HOST'],
                int(CONFIG.REMOTE['PORT']),
                CONFIG.REMOTE['USER'],
                CONFIG.REMOTE['PASSWORD']
            )

            if not ssh:
                st.error("No se pudo obtener conexión del pool")
                return None

            # Verificar que la conexión esté activa
            try:
                transport = ssh.get_transport()
                if transport and transport.is_active():
                    if CONFIG.DEBUG_MODE:
                        pool_status = CONNECTION_POOL.get_pool_status()
                        st.info(f"Pool status: {pool_status}")
                    return ssh
                else:
                    st.error("Conexión SSH obtenida pero no activa")
                    return None
            except Exception as e:
                st.error(f"Error verificando conexión SSH: {str(e)}")
                return None

        except Exception as e:
            st.error(f"Error obteniendo conexión del pool: {str(e)}")
            if CONFIG.DEBUG_MODE:
                import traceback
                st.error(f"Traceback: {traceback.format_exc()}")
            return None

    @staticmethod
    def return_connection(ssh_connection):
        """Devuelve una conexión al pool"""
        return CONNECTION_POOL.return_connection(ssh_connection)

    @staticmethod
    @synchronized("sftp_operations")
    def get_remote_file(remote_filename, timeout=30):
        """Lee archivo remoto con manejo de errores usando pool y timeout"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return None

        sftp = None
        try:
            sftp = ssh.open_sftp()
            sftp.get_channel().settimeout(timeout * 1000)

            remote_path = os.path.join(CONFIG.REMOTE['DIR'], remote_filename)

            if CONFIG.DEBUG_MODE:
                st.info(f"Intentando leer archivo remoto: {remote_path} (timeout: {timeout}s)")

            start_time = time.time()

            # Leer como binario primero y luego decodificar
            with sftp.open(remote_path, 'rb') as f:
                content_bytes = f.read()

            # Convertir a string si es texto
            try:
                content = content_bytes.decode('utf-8')
            except UnicodeDecodeError:
                content = content_bytes

            if CONFIG.DEBUG_MODE:
                elapsed = time.time() - start_time
                content_type = "text" if isinstance(content, str) else "binary"
                st.info(f"Archivo leído correctamente. Tipo: {content_type}, Tamaño: {len(content)} bytes, tiempo: {elapsed:.2f}s")

            return content

        except socket.timeout:
            st.error(f"Timeout leyendo archivo remoto: {remote_filename} (>{timeout}s)")
            return None
        except FileNotFoundError:
            st.error(f"Archivo no encontrado en servidor: {remote_filename}")
            return None
        except Exception as e:
            st.error(f"Error leyendo archivo remoto: {str(e)}")
            if CONFIG.DEBUG_MODE:
                import traceback
                st.error(f"Traceback: {traceback.format_exc()}")
            return None
        finally:
            if sftp:
                try:
                    sftp.close()
                except Exception as e:
                    if CONFIG.DEBUG_MODE:
                        st.error(f"Error cerrando SFTP: {str(e)}")
            SSHManager.return_connection(ssh)

    @staticmethod
    @synchronized("sftp_operations")
    def put_remote_file(remote_path, content, timeout=30):
        """Escribe archivo remoto usando pool con timeout"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return False

        sftp = None
        temp_file_path = None
        try:
            sftp = ssh.open_sftp()
            sftp.get_channel().settimeout(timeout * 1000)

            # Crear directorios si no existen
            remote_dir = os.path.dirname(remote_path)
            try:
                sftp.listdir(remote_dir)
            except (IOError, OSError):
                try:
                    # Crear directorios recursivamente
                    parts = remote_dir.split('/')
                    current_path = ''
                    for part in parts:
                        if part:
                            current_path = current_path + '/' + part if current_path else part
                            try:
                                sftp.listdir(current_path)
                            except (IOError, OSError):
                                sftp.mkdir(current_path)
                                if CONFIG.DEBUG_MODE:
                                    st.info(f"Directorio creado: {current_path}")
                except Exception as e:
                    st.error(f"Error creando directorio {remote_dir}: {str(e)}")
                    return False

            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp', encoding='utf-8') as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            # Subir archivo
            start_time = time.time()
            sftp.put(temp_file_path, remote_path)

            if CONFIG.DEBUG_MODE:
                elapsed = time.time() - start_time
                st.info(f"Archivo subido exitosamente: {remote_path}, tiempo: {elapsed:.2f}s")
            return True

        except socket.timeout:
            st.error(f"Timeout subiendo archivo: {remote_path} (>{timeout}s)")
            return False
        except Exception as e:
            st.error(f"Error subiendo archivo al servidor: {str(e)}")
            if CONFIG.DEBUG_MODE:
                import traceback
                st.error(f"Traceback: {traceback.format_exc()}")
            return False
        finally:
            # Limpiar archivo temporal
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
            # Cerrar conexiones
            if sftp:
                try:
                    sftp.close()
                except Exception as e:
                    if CONFIG.DEBUG_MODE:
                        st.error(f"Error cerrando SFTP: {str(e)}")
            SSHManager.return_connection(ssh)

    @staticmethod
    def _create_remote_dirs(sftp, remote_dir):
        """Función auxiliar para crear directorios remotos recursivamente"""
        if remote_dir == '' or remote_dir == '/':
            return

        parent_dir = os.path.dirname(remote_dir)
        if parent_dir and parent_dir != '/':
            try:
                sftp.listdir(parent_dir)
            except (IOError, OSError):
                SSHManager._create_remote_dirs(sftp, parent_dir)

        try:
            sftp.mkdir(remote_dir)
        except (IOError, OSError):
            pass  # El directorio ya existe

    @staticmethod
    def ensure_remote_directory_exists(sftp, remote_path):
        """Asegura que el directorio remoto exista"""
        remote_dir = os.path.dirname(remote_path)
        try:
            sftp.listdir(remote_dir)
            return True
        except FileNotFoundError:
            try:
                # Crear directorios recursivamente
                parts = remote_dir.split('/')
                current_path = ''
                for part in parts:
                    if part:
                        current_path = current_path + '/' + part if current_path else part
                        try:
                            sftp.listdir(current_path)
                        except FileNotFoundError:
                            sftp.mkdir(current_path)
                            if CONFIG.DEBUG_MODE:
                                st.info(f"Directorio creado: {current_path}")
                return True
            except Exception as e:
                st.error(f"Error creando directorio {remote_dir}: {str(e)}")
                return False

# ====================
# FUNCIONES DE GESTIÓN DE JORNADA (MEJORADAS)
# ====================
@synchronized("csv_files")
def load_csv_data(filename):
    """Carga datos desde un archivo CSV remoto"""
    if CONFIG.DEBUG_MODE:
        st.info(f"Cargando archivo: {filename}")

    csv_content = SSHManager.get_remote_file(filename)

    if not csv_content:
        st.error(f"No se pudo cargar el archivo {filename}")
        return None

    try:
        # Convertir bytes a string si es necesario
        if isinstance(csv_content, bytes):
            csv_content = csv_content.decode('utf-8')

        df = pd.read_csv(StringIO(csv_content))

        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].astype(str).str.strip()

        if 'hora_entrada' in df.columns:
            df['hora_entrada'] = df['hora_entrada'].astype(str).str.strip().str.upper()
            df['hora_entrada'] = df['hora_entrada'].replace(['NAN', 'NONE', 'NUL', ''], '')
            df['hora_entrada'] = df['hora_entrada'].replace('NO', '')

        if 'incidencias' in df.columns:
            df['incidencias'] = df['incidencias'].astype(str).str.strip().str.upper()
            df['incidencias'] = df['incidencias'].replace(['NAN', 'NONE', 'NUL', ''], 'NO')

        if CONFIG.DEBUG_MODE:
            st.info(f"Archivo {filename} cargado correctamente. Filas: {len(df)}")

        return df
    except Exception as e:
        st.error(f"Error procesando archivo {filename}: {str(e)}")
        return None

@lru_cache(maxsize=32)
def load_csv_data_cached(filename):
    """Carga datos desde CSV con caché para mejorar rendimiento"""
    return load_csv_data(filename)


@synchronized("sftp_operations")
def agregar_contenido_a_archivo_remoto(remote_path, nuevo_contenido, timeout=30):
    """Agrega contenido a un archivo remoto existente con timeout"""
    ssh = SSHManager.get_connection()
    if not ssh:
        return False

    sftp = None
    temp_file_path = None
    try:
        sftp = ssh.open_sftp()
        sftp.get_channel().settimeout(timeout * 1000)

        # Asegurar que el directorio existe
        if not SSHManager.ensure_remote_directory_exists(sftp, remote_path):
            return False

        # Leer contenido existente
        try:
            with sftp.open(remote_path, 'rb') as f:
                contenido_actual_bytes = f.read()

            try:
                contenido_actual = contenido_actual_bytes.decode('utf-8')
            except UnicodeDecodeError:
                contenido_actual = contenido_actual_bytes.decode('latin-1')

        except FileNotFoundError:
            contenido_actual = "fecha,tipo,nombre,info,desde,hacia,color,estado,id_persona,numero_economico,expediente\n"
        except Exception as e:
            if "timed out" in str(e).lower():
                st.error(f"Timeout leyendo archivo existente: {remote_path}")
                return False
            raise e

        if isinstance(contenido_actual, bytes):
            try:
                contenido_actual = contenido_actual.decode('utf-8')
            except UnicodeDecodeError:
                contenido_actual = contenido_actual.decode('latin-1')

        if isinstance(nuevo_contenido, bytes):
            try:
                nuevo_contenido = nuevo_contenido.decode('utf-8')
            except UnicodeDecodeError:
                nuevo_contenido = nuevo_contenido.decode('latin-1')

        # Combinar contenido
        contenido_combinado = contenido_actual + nuevo_contenido

        # Crear archivo temporal
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp', encoding='utf-8') as temp_file:
            temp_file.write(contenido_combinado)
            temp_file_path = temp_file.name

        # Subir archivo
        start_time = time.time()
        sftp.put(temp_file_path, remote_path)

        if CONFIG.DEBUG_MODE:
            elapsed = time.time() - start_time
            st.info(f"Contenido agregado exitosamente a: {remote_path}, tiempo: {elapsed:.2f}s")
        return True

    except socket.timeout:
        st.error(f"Timeout actualizando archivo: {remote_path}")
        return False
    except Exception as e:
        st.error(f"Error actualizando archivo en servidor: {str(e)}")
        return False
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except:
                pass
        if sftp:
            try:
                sftp.close()
            except:
                pass
        SSHManager.return_connection(ssh)


# ====================
# FUNCIONES DEL LOG (MEJORADAS CON NUEVO SISTEMA DE RUTAS)
# ====================
@synchronized("log_files")
def listar_logs_disponibles(user_info, timeout=30):
    """Lista los archivos de log disponibles para este usuario con timeout"""
    try:
        ssh = SSHManager.get_connection()
        if not ssh:
            return []

        sftp = None
        try:
            sftp = ssh.open_sftp()
            sftp.get_channel().settimeout(timeout * 1000)

            # CORRECCIÓN: Directorio del usuario específico con número económico
            user_log_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_servicios", user_info['numero_economico'])

            try:
                files = sftp.listdir(user_log_dir)
                transferencias_pattern = ".transferencias.csv"
                user_logs = [f for f in files if transferencias_pattern in f]
                return sorted(user_logs, reverse=True)

            except FileNotFoundError:
                if CONFIG.DEBUG_MODE:
                    st.info(f"Directorio no encontrado: {user_log_dir}")
                return []
            except Exception as e:
                if "timed out" in str(e).lower():
                    st.error("Timeout listando directorio de logs")
                else:
                    if CONFIG.DEBUG_MODE:
                        st.error(f"Error accediendo al directorio: {str(e)}")
                return []

        finally:
            if sftp:
                try:
                    sftp.close()
                except:
                    pass
            SSHManager.return_connection(ssh)

    except Exception as e:
        if CONFIG.DEBUG_MODE:
            st.error(f"Error listando logs: {str(e)}")
        return []


@synchronized("log_files")
def registrar_transferencia(user_info, tipo, nombre, info, desde, hacia, color, estado="completado", expediente=""):
    """Registra una transferencia en el log del usuario con manejo de concurrencia mejorado"""
    fecha_actual = datetime.now(pytz.timezone('America/Mexico_City')).strftime("%y-%m-%d:%H:%M:%S")
    id_persona = str(uuid.uuid4())
    numero_economico = user_info.get('numero_economico', '')

    nueva_linea = f"{fecha_actual},{tipo},{nombre},{info},{desde},{hacia},{color},{estado},{id_persona},{numero_economico},{expediente}\n"

    # CORRECCIÓN CRÍTICA: Usar timestamp con microsegundos para evitar nombres idénticos
    timestamp_actual = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")  # Agregar microsegundos
    log_filename = f"{timestamp_actual}-{user_info['servicio']}.transferencias.csv"

    # CORRECCIÓN CRÍTICA: Ruta corregida - crear directorio con número económico del usuario
    user_log_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_servicios", user_info['numero_economico'])
    user_log_path = os.path.join(user_log_dir, log_filename)

    if CONFIG.DEBUG_MODE:
        st.info(f"Registrando transferencia: {nueva_linea.strip()}")
        st.info(f"Ruta del log: {user_log_path}")

    # CORRECCIÓN: Crear directorio del usuario si no existe
    ssh = SSHManager.get_connection()
    if not ssh:
        return False

    sftp = None
    try:
        sftp = ssh.open_sftp()
        sftp.get_channel().settimeout(30)

        # CORRECCIÓN: Asegurar que el directorio del usuario existe
        try:
            sftp.listdir(user_log_dir)
            if CONFIG.DEBUG_MODE:
                st.info(f"✅ Directorio ya existe: {user_log_dir}")
        except FileNotFoundError:
            # Crear directorio recursivamente
            SSHManager._create_remote_dirs(sftp, user_log_dir)
            if CONFIG.DEBUG_MODE:
                st.info(f"✅ Directorio creado: {user_log_dir}")

    except Exception as e:
        st.error(f"Error creando directorio de logs: {str(e)}")
        return False
    finally:
        if sftp:
            try:
                sftp.close()
            except:
                pass
        SSHManager.return_connection(ssh)

    # Agregar la nueva línea al archivo
    success = agregar_contenido_a_archivo_remoto(user_log_path, nueva_linea)

    if success and CONFIG.DEBUG_MODE:
        st.success(f"✅ Transferencia registrada en: {log_filename}")

    return success


# ====================
# FUNCIONES DE VERIFICACIÓN DE DUPLICADOS (OPTIMIZADAS)
# ====================
@synchronized("session_files")
def verificar_duplicados_enfermeras():
    """Función optimizada para verificar y mostrar duplicados en los datos"""
    if 'habitaciones' not in st.session_state:
        st.warning("No hay habitaciones cargadas para verificar")
        return []

    todas_enfermeras = []
    for habitacion, datos in st.session_state.habitaciones.items():
        for enfermera in datos["enfermeras"]:
            todas_enfermeras.append({
                'nombre': enfermera['nombre'],
                'habitacion': habitacion,
                'numero_economico': enfermera.get('numero_economico', 'N/A'),
                'id': enfermera.get('id', 'N/A')
            })

    numeros_economicos_vistos = set()
    duplicados = []

    for enf in todas_enfermeras:
        numero_economico = enf['numero_economico']
        if numero_economico in numeros_economicos_vistos:
            duplicados.append({
                'nombre': enf['nombre'],
                'numero_economico': numero_economico,
                'habitacion_duplicado': enf['habitacion'],
                'id_duplicado': enf['id']
            })
        else:
            numeros_economicos_vistos.add(numero_economico)

    if duplicados:
        st.error("⚠️ DUPLICADOS ENCONTRADOS (POR NÚMERO ECONÓMICO):")
        for dup in duplicados:
            st.error(f"- {dup['nombre']} (No. Econ: {dup['numero_economico']})")
            st.error(f"  Duplicado en: {dup['habitacion_duplicado']} (ID: {dup['id_duplicado']})")

        if st.button("🗑️ Eliminar duplicados automáticamente", key="btn_eliminar_duplicados"):
            eliminar_duplicados_automaticamente(duplicados)
            st.rerun()

    return duplicados

@synchronized("session_files")
def eliminar_duplicados_automaticamente(duplicados):
    """Elimina duplicados automáticamente manteniendo solo la primera ocurrencia"""
    if not duplicados:
        return

    ids_a_eliminar = set()
    numeros_economicos_procesados = set()

    for dup in duplicados:
        ids_a_eliminar.add(dup['id_duplicado'])
        numeros_economicos_procesados.add(dup['numero_economico'])

    enfermeras_eliminadas = 0
    for habitacion, datos in st.session_state.habitaciones.items():
        enfermeras_originales = len(datos["enfermeras"])
        datos["enfermeras"] = [enf for enf in datos["enfermeras"] if enf.get('id') not in ids_a_eliminar]
        enfermeras_eliminadas += (enfermeras_originales - len(datos["enfermeras"]))

    st.success(f"✅ {enfermeras_eliminadas} duplicados eliminados")
    st.info(f"📋 Números económicos procesados: {', '.join(numeros_economicos_procesados)}")


# ====================
# FUNCIONES DE AUTENTICACIÓN
# ====================
def authenticate_user():
    """Autentica al usuario verificando en ambos archivos CSV"""
    st.title("🔐 Sistema de Jefatura Servicio - Modo Registro")

    if 'auth_stage' not in st.session_state:
        st.session_state.auth_stage = 'numero_economico'

    if 'numero_economico' not in st.session_state:
        st.session_state.numero_economico = ''

    if st.session_state.auth_stage == 'numero_economico':
        with st.form("auth_form_numero"):
            numero_economico = st.text_input("Número Económico", max_chars=10).strip()
            submitted = st.form_submit_button("Verificar")

            if submitted:
                if not numero_economico:
                    st.error("Por favor ingrese su número económico")
                    return False, None

                st.session_state.numero_economico = numero_economico
                st.info(f"🔍 Verificando número económico: '{numero_economico}'")

                st.info("⏳ Cargando archivo de enfermeras...")
                enfermeras_df = load_csv_data_cached(CONFIG.FILES["enfermeras"])

                st.info("⏳ Cargando archivo de claves...")
                claves_df = load_csv_data_cached(CONFIG.FILES["claves"])

                if enfermeras_df is None or claves_df is None:
                    st.error("No se pudieron cargar los archivos necesarios para autenticación")
                    return False, None

                required_enfermeras = ['numero_economico', 'puesto', 'nombre_completo', 'incidencias', 'servicio', 'turno_laboral', 'fecha_turno']
                for col in required_enfermeras:
                    if col not in enfermeras_df.columns:
                        st.error(f"❌ La columna '{col}' no existe en el archivo de enfermeras")
                        return False, None

                required_claves = ['numero_economico', 'password']
                for col in required_claves:
                    if col not in claves_df.columns:
                        st.error(f"❌ La columna '{col}' no existe en el archivo de claves")
                        return False, None

                enfermeras_df['numero_economico'] = enfermeras_df['numero_economico'].astype(str).str.strip()
                claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
                numero_clean = numero_economico.strip()

                in_enfermeras = numero_clean in enfermeras_df['numero_economico'].values
                in_claves = numero_clean in claves_df['numero_economico'].values

                if not in_enfermeras or not in_claves:
                    st.error("❌ Número económico no registrado o sin permisos")
                    return False, None

                user_data = enfermeras_df[enfermeras_df['numero_economico'] == numero_clean].iloc[0]
                puesto = user_data['puesto'].strip().lower()
                servicio = user_data['servicio'].strip() if 'servicio' in user_data and not pd.isna(user_data['servicio']) else ""
                turno_laboral = user_data['turno_laboral'].strip() if 'turno_laboral' in user_data and not pd.isna(user_data['turno_laboral']) else ""
                fecha_turno = user_data['fecha_turno'].strip() if 'fecha_turno' in user_data and not pd.isna(user_data['fecha_turno']) else ""

                if puesto != "jefatura servicio":
                    st.error("❌ Solo personal con puesto 'jefatura servicio' puede acceder al sistema")
                    return False, None

                incidencias = user_data['incidencias']
                incidencias_str = str(incidencias).strip().upper() if not pd.isna(incidencias) else ""

                incidencias_invalidas = ['DS', 'VA', 'VR', 'VP', 'ON', 'DE', 'AC', 'BE', 'FE', 'CO', 'FA', 'SU', 'SL', 'IN', 'IG', 'CM', 'LC', 'LS', 'LI', 'NC']

                if incidencias_str in incidencias_invalidas:
                    st.error("❌ Usuario con incidencias registradas. No puede acceder al sistema.")
                    return False, None

                st.session_state.auth_stage = 'password'
                st.session_state.user_data = {
                    'numero_economico': numero_clean,
                    'nombre_completo': user_data['nombre_completo'],
                    'puesto': puesto,
                    'servicio': servicio,
                    'turno_laboral': turno_laboral,
                    'fecha_turno': fecha_turno
                }
                st.rerun()

    elif st.session_state.auth_stage == 'password':
        with st.form("auth_form_password"):
            st.info(f"Verificando usuario: {st.session_state.user_data['nombre_completo']}")
            st.info(f"Servicio: {st.session_state.user_data['servicio']}")
            st.info(f"Turno: {st.session_state.user_data['turno_laboral']}")
            st.info(f"Fecha turno: {st.session_state.user_data['fecha_turno']}")
            password = st.text_input("Contraseña", type="password")
            confirm = st.form_submit_button("Validar Contraseña")

            if confirm:
                if not password:
                    st.error("❌ Por favor ingrese su contraseña")
                    return False, None

                claves_df = load_csv_data_cached(CONFIG.FILES["claves"])
                if claves_df is None:
                    st.error("No se pudo cargar el archivo de claves")
                    return False, None

                claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
                user_clave = claves_df[claves_df['numero_economico'] == st.session_state.numero_economico].iloc[0]

                if user_clave['password'] != password:
                    st.error("❌ Contraseña incorrecta")
                    return False, None

                st.success("✅ Autenticación exitosa")
                st.session_state.auth_stage = 'authenticated'
                st.rerun()

    elif st.session_state.auth_stage == 'authenticated':
        return True, {
            'numero_economico': st.session_state.numero_economico,
            'nombre': st.session_state.user_data['nombre_completo'],
            'puesto': st.session_state.user_data['puesto'],
            'servicio': st.session_state.user_data['servicio'],
            'turno_laboral': st.session_state.user_data['turno_laboral'],
            'fecha_turno': st.session_state.user_data['fecha_turno']
        }

    return False, None


# ====================
# FUNCIONES DE ESTRUCTURA DE HABITACIONES (CORREGIDAS)
# ====================
def crear_estructura_habitaciones(user_servicio, pacientes_servicio, enfermeras_servicio):
    """Crea la estructura inicial de habitaciones basada en la configuración de camas por servicio"""

    habitaciones = {}

    # VERIFICAR SI EL SERVICIO TIENE CONFIGURACIÓN ESPECÍFICA DE CAMAS
    servicio_upper = user_servicio.strip().upper()

    if servicio_upper in CONFIG.CAMAS_POR_SERVICIO:
        # CREAR HABITACIONES BASADAS EN LA CONFIGURACIÓN DEL SERVICIO
        config_servicio = CONFIG.CAMAS_POR_SERVICIO[servicio_upper]
        rango_inicio = config_servicio["rango_inicio"]
        rango_fin = config_servicio["rango_fin"]
        total_camas = config_servicio["total_camas"]

        if CONFIG.DEBUG_MODE:
            st.info(f"Creando {total_camas} camas para servicio {servicio_upper}: del {rango_inicio} al {rango_fin}")

        # CORRECCIÓN: Crear todas las camas del rango configurado SIN servicio en el nombre
        for cama_num in range(rango_inicio, rango_fin + 1):
            habitacion_nombre = f"Cama {cama_num}"  # SIN servicio en el nombre
            habitaciones[habitacion_nombre] = {"pacientes": [], "enfermeras": []}

        if CONFIG.DEBUG_MODE:
            st.info(f"Se crearon {len(habitaciones)} habitaciones para {servicio_upper}")
    else:
        # COMPORTAMIENTO ORIGINAL: crear habitaciones basadas en pacientes existentes
        if not pacientes_servicio.empty and 'numero_cama' in pacientes_servicio.columns:
            camas_unicas = pacientes_servicio['numero_cama'].unique()

            def ordenar_camas(camas):
                try:
                    return sorted(camas, key=lambda x: int(x) if str(x).isdigit() else 0)
                except:
                    return camas

            camas_ordenadas = ordenar_camas(camas_unicas)

            for cama in camas_ordenadas:
                # CORRECCIÓN: Nombre de habitación sin servicio
                habitacion_nombre = f"Cama {cama}"
                habitaciones[habitacion_nombre] = {"pacientes": [], "enfermeras": []}
        else:
            # CORRECCIÓN: Nombre de habitación sin servicio
            habitaciones["Sala Principal"] = {"pacientes": [], "enfermeras": []}

    # CORRECCIÓN CRÍTICA: FILTRAR ENFERMERAS POR FECHA_TURNO, SERVICIO Y TURNO_LABORAL
    if not enfermeras_servicio.empty:
        # Obtener información del usuario actual
        user_info = st.session_state.user_data if 'user_data' in st.session_state else {}
        user_fecha_turno = user_info.get('fecha_turno', '')
        user_servicio_filter = user_info.get('servicio', '')
        user_turno_laboral = user_info.get('turno_laboral', '')

        # CORRECCIÓN: Definir puestos válidos específicos
        puestos_validos = [
            'enfermera general a', 'enfermera general b', 'enfermera general c',
            'enfermera especialista', 'ayudante general', 'camillero'
        ]

        # CORRECCIÓN: Filtrar enfermeras por fecha_turno, servicio y turno_laboral
        enfermeras_validas = enfermeras_servicio[
            (enfermeras_servicio['fecha_turno'].astype(str).str.strip() == user_fecha_turno) &
            (enfermeras_servicio['servicio'].str.strip().str.lower() == user_servicio_filter.lower()) &
            (enfermeras_servicio['turno_laboral'].str.strip().str.lower() == user_turno_laboral.lower()) &
            (~enfermeras_servicio['hora_entrada'].isna()) &
            (enfermeras_servicio['hora_entrada'].astype(str).str.strip() != '') &
            (enfermeras_servicio['incidencias'].astype(str).str.strip().str.upper() == 'NO') &
            (enfermeras_servicio['puesto'].str.strip().str.lower().isin(puestos_validos))
        ].copy()

        # Eliminar duplicados por número económico
        enfermeras_validas = enfermeras_validas.drop_duplicates(subset=['numero_economico'], keep='first')

        if CONFIG.DEBUG_MODE:
            st.info(f"Enfermeras válidas después de filtrar: {len(enfermeras_validas)}")
            st.info(f"Criterios de filtrado:")
            st.info(f"- Fecha turno: {user_fecha_turno}")
            st.info(f"- Servicio: {user_servicio_filter}")
            st.info(f"- Turno laboral: {user_turno_laboral}")
            st.info(f"- Puestos válidos: {puestos_validos}")

            if not enfermeras_validas.empty:
                st.info("Ejemplo de enfermeras válidas encontradas:")
                for _, enf in enfermeras_validas.head(3).iterrows():
                    st.info(f"  - {enf['nombre_completo']} (No. {enf['numero_economico']}) - Puesto: {enf['puesto']}")

        # Distribuir enfermeras válidas en las habitaciones
        habitaciones_list = list(habitaciones.keys())

        if habitaciones_list and not enfermeras_validas.empty:
            if CONFIG.DEBUG_MODE:
                st.info(f"Habitaciones disponibles: {len(habitaciones_list)}")
                st.info(f"Enfermeras a distribuir: {len(enfermeras_validas)}")

            enfermeras_asignadas = set()

            for i, (_, enfermera) in enumerate(enfermeras_validas.iterrows()):
                numero_economico = enfermera['numero_economico']

                if numero_economico in enfermeras_asignadas:
                    if CONFIG.DEBUG_MODE:
                        st.warning(f"⚠️ Saltando enfermera duplicada: {enfermera['nombre_completo']} (No. {numero_economico})")
                    continue

                habitacion_idx = i % len(habitaciones_list)
                habitacion = habitaciones_list[habitacion_idx]

                # CORRECCIÓN: Extraer número de cama del nombre de la habitación (sin servicio)
                numero_cama = "0"
                if "Cama" in habitacion:
                    try:
                        numero_cama = habitacion.split("Cama ")[1].strip()
                    except:
                        numero_cama = "0"

                puesto = enfermera['puesto'].strip().lower()
                if 'especialista' in puesto:
                    color = "#9c27b0"
                    rol = "Especialista"
                elif 'general a' in puesto:
                    color = "#2196f3"
                    rol = "General A"
                elif 'general b' in puesto:
                    color = "#ff9800"
                    rol = "General B"
                elif 'general c' in puesto:
                    color = "#4caf50"
                    rol = "General C"
                elif 'camillero' in puesto or 'ayudante' in puesto:
                    color = "#607d8b"
                    rol = "Ayudante/Camillero"
                else:
                    color = "#9c27b0"
                    rol = "General A"

                enfermera_id = f"enfermera_{numero_economico}_{enfermera['nombre_completo'].replace(' ', '_')}"

                habitaciones[habitacion]["enfermeras"].append({
                    "id": enfermera_id,
                    "tipo": "enfermera",
                    "nombre": f"Enf: {enfermera['nombre_completo']}",
                    "rol": rol,
                    "color": color,
                    "numero_economico": numero_economico,
                    "hora_entrada": enfermera['hora_entrada'],
                    "fecha_turno": enfermera.get('fecha_turno', ''),
                    "numero_cama": numero_cama
                })

                enfermeras_asignadas.add(numero_economico)

                if CONFIG.DEBUG_MODE:
                    st.info(f"✓ Asignada: {enfermera['nombre_completo']} a {habitacion}")

    # CORRECCIÓN: AGREGAR PACIENTES - SOLO FILTRAR POR SERVICIO
    if not pacientes_servicio.empty:
        # CORRECCIÓN: Filtrar pacientes solo por servicio
        pacientes_filtrados = pacientes_servicio[
            pacientes_servicio['servicio'].str.strip().str.lower() == user_servicio.lower()
        ]

        if CONFIG.DEBUG_MODE:
            st.info(f"Pacientes después de filtrar por servicio: {len(pacientes_filtrados)}")

        for _, paciente in pacientes_filtrados.iterrows():
            cama = paciente['numero_cama']
            # CORRECCIÓN: Nombre de habitación sin servicio
            habitacion_nombre = f"Cama {cama}"

            if habitacion_nombre not in habitaciones:
                # Si la cama del paciente no existe en la estructura, crearla
                habitaciones[habitacion_nombre] = {"pacientes": [], "enfermeras": []}

            paciente_id = f"paciente_{paciente['nombre_completo'].replace(' ', '_')}_{cama}_{user_servicio}"

            habitaciones[habitacion_nombre]["pacientes"].append({
                "id": paciente_id,
                "tipo": "paciente",
                "nombre": f"Pas: {paciente['nombre_completo']}",
                "diagnostico": paciente.get('diagnostico', ''),
                "estado": "estable",
                "color": "#4caf50",
                "edad": paciente.get('edad', 0),
                "fecha_ingreso": paciente.get('fecha_ingreso', ''),
                "numero_cama": paciente.get('numero_cama', ''),
                "expediente": paciente.get('expediente', '')
            })

    # CORRECCIÓN: Ordenar habitaciones al final
    def ordenar_habitaciones_final(hab_dict):
        """Ordena habitaciones por número de cama"""
        habitaciones_ordenadas = {}

        def extraer_numero(hab_nombre):
            try:
                if "Cama" in hab_nombre:
                    return int(hab_nombre.split("Cama ")[1].strip())
                else:
                    return 0
            except:
                return 0

        claves_ordenadas = sorted(hab_dict.keys(), key=extraer_numero)
        for clave in claves_ordenadas:
            habitaciones_ordenadas[clave] = hab_dict[clave]

        return habitaciones_ordenadas

    return ordenar_habitaciones_final(habitaciones)


# ====================
# INICIALIZACIÓN DEL ESTADO DE SESIÓN (CORREGIDA)
# ====================
@synchronized("session_files")
def initialize_session_state(user_servicio, user_info):
    """Inicializa el estado de la sesión SOLO desde datos originales"""
    try:
        # Inicializar TODAS las variables de session_state PRIMERO
        session_vars = {
            'seleccion': {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None},
            'log_movimientos': [],
            'nuevo_nombre': "",
            'nuevo_diagnostico': CONFIG.DIAGNOSTICOS[0] if CONFIG.DIAGNOSTICOS else "Diagnóstico por definir",
            'nuevo_rol': "General A",
            'tipo_nuevo': "",
            'habitacion_nuevo': "",
            'session_cargada': False,
            'nuevo_numero_economico': "",
            'nuevo_expediente': "",
            'ultimo_inicio_jornada': None
        }

        for key, default_value in session_vars.items():
            if key not in st.session_state:
                st.session_state[key] = default_value

        # SOLO INICIALIZAR DESDE DATOS ORIGINALES - NUNCA desde sesiones guardadas
        if 'habitaciones' not in st.session_state or not st.session_state.habitaciones:
            st.info("⏳ Cargando datos de pacientes y enfermeras...")

            pacientes_df = load_csv_data_cached(CONFIG.FILES["pacientes"])
            enfermeras_df = load_csv_data_cached(CONFIG.FILES["enfermeras"])

            if pacientes_df is None or enfermeras_df is None:
                st.error("No se pudieron cargar los archivos necesarios")
                return

            if CONFIG.DEBUG_MODE:
                st.info("✅ Archivos CSV cargados correctamente")
                st.info(f"Columnas en pacientes: {list(pacientes_df.columns)}")
                st.info(f"Columnas en enfermeras: {list(enfermeras_df.columns)}")

            # CORRECCIÓN: Filtrar pacientes solo por servicio
            pacientes_servicio = pacientes_df[
                pacientes_df['servicio'].str.strip().str.lower() == user_servicio.lower()
            ]

            if CONFIG.DEBUG_MODE:
                st.info(f"Pacientes después de filtrar por servicio '{user_servicio}': {len(pacientes_servicio)}")

            # CORRECCIÓN CRÍTICA: Filtrar enfermeras por fecha_turno, servicio y turno_laboral
            user_fecha_turno = user_info.get('fecha_turno', '')
            user_turno_laboral = user_info.get('turno_laboral', '')

            if CONFIG.DEBUG_MODE:
                st.info(f"Filtrando enfermeras con:")
                st.info(f"- Servicio: {user_servicio}")
                st.info(f"- Fecha turno: {user_fecha_turno}")
                st.info(f"- Turno laboral: {user_turno_laboral}")

            # Asegurar que las columnas existan y tengan el formato correcto
            if 'fecha_turno' not in enfermeras_df.columns:
                st.error("❌ La columna 'fecha_turno' no existe en el archivo de enfermeras")
                return

            if 'turno_laboral' not in enfermeras_df.columns:
                st.error("❌ La columna 'turno_laboral' no existe en el archivo de enfermeras")
                return

            # Filtrar enfermeras
            enfermeras_servicio = enfermeras_df[
                (enfermeras_df['servicio'].str.strip().str.lower() == user_servicio.lower()) &
                (enfermeras_df['fecha_turno'].astype(str).str.strip() == user_fecha_turno) &
                (enfermeras_df['turno_laboral'].str.strip().str.lower() == user_turno_laboral.lower())
            ]

            if CONFIG.DEBUG_MODE:
                st.info(f"Enfermeras después de filtrar: {len(enfermeras_servicio)}")
                if not enfermeras_servicio.empty:
                    st.info("Primeras 3 enfermeras encontradas:")
                    for i, (_, enf) in enumerate(enfermeras_servicio.head(3).iterrows()):
                        st.info(f"  {i+1}. {enf.get('nombre_completo', 'N/A')} - {enf.get('puesto', 'N/A')}")

            # Crear estructura de habitaciones
            habitaciones = crear_estructura_habitaciones(user_servicio, pacientes_servicio, enfermeras_servicio)

            if habitaciones:
                st.session_state.habitaciones = habitaciones
                st.session_state.session_cargada = False

                if CONFIG.DEBUG_MODE:
                    st.info(f"✅ Habitaciones creadas exitosamente: {len(habitaciones)} habitaciones")
                    total_pacientes = sum(len(h['pacientes']) for h in habitaciones.values())
                    total_enfermeras = sum(len(h['enfermeras']) for h in habitaciones.values())
                    st.info(f"📊 Resumen: {total_pacientes} pacientes, {total_enfermeras} enfermeras")
            else:
                st.error("❌ No se pudieron crear las habitaciones. Verifica los datos de entrada.")

    except Exception as e:
        st.error(f"❌ Error inicializando el estado de sesión: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback: {traceback.format_exc()}")

# ====================
# FUNCIONES DE INTERFAZ
# ====================
def setup_page_config():
    """Configura la página de Streamlit"""
    st.set_page_config(
        layout="wide",
        page_title="Sistema de Jefatura Servicio - Modo Registro",
        page_icon="🏥"
    )

def load_custom_styles():
    """Carga los estilos CSS personalizados"""
    st.markdown("""
        <style>
        .header-container {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }
        .logo-img {
            max-height: 80px;
        }
        .habitacion-container {
            border: 2px solid #4a8cff;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #f8fbff;
        }
        .habitacion-header {
            font-size: 1.3em;
            font-weight: bold;
            color: #2c5fd1;
            margin-bottom: 15px;
            text-align: center;
        }
        .persona-container {
            display: flex;
            flex-direction: column;
            padding: 12px;
            margin: 8px 0;
            background-color: white;
            border-radius: 8px;
            border: 1px solid #ddd;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .persona-container:hover {
            background-color: #f0f6ff;
        }
        .selected {
            background-color: #fff8e1 !important;
            border: 2px solid #ffd54f !important;
        }
        .estado-badge {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            display: inline-block;
            margin-left: 8px;
        }
        .persona-name {
            font-weight: bold;
            font-size: 1.05em;
            margin-bottom: 4px;
        }
        .persona-info {
            font-size: 0.85em;
            color: #555;
            margin-bottom: 6px;
        }
        .historial-item {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 12px;
            border-left: 4px solid #4a8cff;
            font-size: 0.85em;
        }
        .leyenda-horizontal {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 15px;
            justify-content: center;
            padding: 10px;
            background-color: #f0f8ff;
            border-radius: 5px;
        }
        .leyenda-item {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.85em;
            white-space: nowrap;
        }
        .sumario-cambios {
            margin-top: 30px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #4a8cff;
        }
        .seleccionado-box {
            background-color: #fff8e1;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 15px;
            border: 1px solid #ffd54f;
        }
        .boton-accion {
            margin: 5px 0;
            width: 100%;
        }
        .badge-container {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            margin-top: 4px;
        }
        .seccion-enfermeras {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px dashed #ccc;
        }
        .seccion-enfermeras-title {
            font-size: 0.9em;
            font-weight: bold;
            color: #555;
            margin-bottom: 10px;
        }
        .boton-agregar {
            margin-top: 10px;
        }
        .formulario-alta {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            border-left: 4px solid #4a8cff;
        }
        </style>
    """, unsafe_allow_html=True)

def image_to_base64(image):
    """Convierte una imagen a base64"""
    buffered = BytesIO()
    image.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

def show_logo():
    """Muestra el logo en la parte superior"""
    try:
        logo_path = "escudo_COLOR.jpg"
        logo = Image.open(logo_path)
        st.markdown(
            """
            <div class="header-container">
                <img src="data:image/png;base64,{}" class="logo-img">
            </div>
            """.format(image_to_base64(logo)),
            unsafe_allow_html=True
        )

        if CONFIG.DEBUG_MODE:
            st.success(f"✅ Logo cargado correctamente: {logo_path}")

    except FileNotFoundError:
        st.markdown('<div class="header-container"><h2>🏥 Sistema de Gestión de Pacientes y Enfermeras</h2></div>', unsafe_allow_html=True)
        if CONFIG.DEBUG_MODE:
            st.warning(f"⚠️ Archivo de logo no encontrado: {logo_path}")

    except Exception as e:
        st.markdown('<div class="header-container"><h2>🏥 Sistema de Gestión de Pacientes y Enfermeras</h2></div>', unsafe_allow_html=True)
        if CONFIG.DEBUG_MODE:
            st.error(f"❌ Error cargando logo: {str(e)}")


# ====================
# FUNCIONES DE GESTIÓN DE JORNADA (OPTIMIZADAS)
# ====================
@synchronized("session_files")
def incrementar_numero_consecutivo(user_info):
    """Incrementa el número consecutivo del usuario en el archivo de claves"""
    try:
        content = SSHManager.get_remote_file(CONFIG.FILES["claves"])
        if not content:
            st.error("No se pudo cargar el archivo de claves")
            return False

        claves_df = pd.read_csv(StringIO(content))
        claves_df.columns = claves_df.columns.str.strip().str.lower()

        if 'numero_economico' in claves_df.columns:
            claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()

        usuario_id_buscado = str(user_info['numero_economico']).strip()
        usuario_encontrado = claves_df[claves_df['numero_economico'] == usuario_id_buscado]

        if usuario_encontrado.empty:
            st.error(f"❌ Usuario {usuario_id_buscado} no encontrado en el archivo de claves")
            return False

        usuario_idx = usuario_encontrado.index[0]
     #   numero_actual = int(claves_df.loc[usuario_idx, 'numero_consecutivo'])
     #   nuevo_numero = numero_actual + 1
   #     claves_df.loc[usuario_idx, 'numero_consecutivo'] = nuevo_numero

        csv_content = claves_df.to_csv(index=False)
        remote_path = os.path.join(CONFIG.REMOTE['DIR'], CONFIG.FILES["claves"])
        success = SSHManager.put_remote_file(remote_path, csv_content)

        if success:
    #        st.success(f"✅ Número consecutivo incrementado: {numero_actual} → {nuevo_numero}")
            return True
        else:
            st.error("❌ Error al actualizar el archivo de claves")
            return False

    except Exception as e:
        st.error(f"❌ Error incrementando número consecutivo: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Detalles del error: {traceback.format_exc()}")
        return False

@synchronized("log_files")
def mover_logs_jornada_anterior(user_info):
    """Mueve los logs de la jornada anterior a la carpeta principal de user_logs_servicios"""
    try:
        ssh = SSHManager.get_connection()
        if not ssh:
            st.error("❌ No se pudo conectar al servidor")
            return False

        sftp = None
        try:
            sftp = ssh.open_sftp()

            # CORRECCIÓN: Directorio origen - carpeta específica del usuario
            user_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_servicios", user_info['numero_economico'])

            # CORRECCIÓN: Directorio destino - nivel superior (16004/user_logs_servicios/)
            servicio_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_servicios")

            try:
                sftp.stat(user_dir)
                archivos = sftp.listdir(user_dir)

                if not archivos:
                    st.info("📝 No hay archivos de log para mover")
                    return True

                # Asegurar que existe el directorio destino (nivel superior)
                try:
                    sftp.stat(servicio_dir)
                except FileNotFoundError:
                    SSHManager.ensure_remote_directory_exists(sftp, os.path.join(servicio_dir, "dummy.txt"))

                movidos_count = 0
                for archivo in archivos:
                    origen_path = os.path.join(user_dir, archivo)
                    destino_path = os.path.join(servicio_dir, archivo)

                    try:
                        sftp.rename(origen_path, destino_path)
                        movidos_count += 1
                        if CONFIG.DEBUG_MODE:
                            st.info(f"📁 Movido: {archivo} a {servicio_dir}")
                    except Exception as e:
                        st.warning(f"⚠️ No se pudo mover {archivo}: {str(e)}")

                st.success(f"✅ Se movieron {movidos_count} archivos de log al directorio del servicio")
                return True

            except FileNotFoundError:
                st.info("📝 No existe directorio de usuario para mover logs")
                return True

            except Exception as e:
                st.error(f"❌ Error moviendo logs: {str(e)}")
                return False

        finally:
            if sftp:
                try:
                    sftp.close()
                except:
                    pass
            SSHManager.return_connection(ssh)

    except Exception as e:
        st.error(f"❌ Error en operación de mover logs: {str(e)}")
        return False

def manejar_inicio_jornada(user_info):
    """Maneja la pregunta de inicio de jornada laboral"""
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🏥 Inicio de Jornada")

    hoy = datetime.now().strftime("%Y-%m-%d")
    if 'ultimo_inicio_jornada' in st.session_state and st.session_state.ultimo_inicio_jornada == hoy:
        st.sidebar.info("✅ Jornada ya iniciada hoy")
        return

    respuesta = st.sidebar.radio(
        "¿Estás iniciando tu jornada laboral?",
        ["No", "Sí"],
        index=0
    )

    if respuesta == "Sí":
        if st.sidebar.button("🔒 Confirmar Inicio de Jornada", use_container_width=True):
            with st.spinner("Procesando inicio de jornada..."):
                if incrementar_numero_consecutivo(user_info):
                    if mover_logs_jornada_anterior(user_info):
                        st.session_state.ultimo_inicio_jornada = hoy
                        st.sidebar.success("🎉 Jornada iniciada correctamente")
                        st.sidebar.info("📁 Logs de jornadas anteriores movidos al directorio del servicio")
                    else:
                        st.sidebar.error("❌ Error moviendo logs de jornada anterior")
                else:
                    st.sidebar.error("❌ Error al incrementar número consecutivo")
    else:
        st.sidebar.info("➡️ Continuando con sesión actual")


def show_estado_legend():
    """Muestra la leyenda de estados y roles en la parte superior"""
    st.markdown("""
    <div class="leyenda-horizontal">
        <div class="leyenda-item">
            <div style="width: 0; height: 0; border-left: 8px solid transparent; border-right: 8px solid transparent; border-bottom: 14px solid #ff0000;"></div>
            <span>Crítico</span>
        </div>
        <div class="leyenda-item">
            <div style="width: 0; height: 0; border-left: 8px solid transparent; border-right: 8px solid transparent; border-bottom: 14px solid #ff6600;"></div>
            <span>Observación</span>
        </div>
        <div class="leyenda-item">
            <div style="width: 0; height: 0; border-left: 8px solid transparent; border-right: 8px solid transparent; border-bottom: 14px solid #0066ff;"></div>
            <span>Mejorando</span>
        </div>
        <div class="leyenda-item">
            <div style="width: 0; height: 0; border-left: 8px solid transparent; border-right: 8px solid transparent; border-bottom: 14px solid #00aa00;"></div>
            <span>Estable</span>
        </div>
    </div>
    <div class="leyenda-horizontal" style="margin-top: 10px;">
        <div class="leyenda-item">
            <div style="width: 14px; height: 14px; background-color: #9c27b0; border-radius: 3px;"></div>
            <span>Especialista</span>
        </div>
        <div class="leyenda-item">
            <div style="width: 14px; height: 14px; background-color: #2196f3; border-radius: 3px;"></div>
            <span>General A</span>
        </div>
        <div class="leyenda-item">
            <div style="width: 14px; height: 14px; background-color: #ff9800; border-radius: 3px;"></div>
            <span>General B</span>
        </div>
        <div class="leyenda-item">
            <div style="width: 14px; height: 14px; background-color: #4caf50; border-radius: 3px;"></div>
            <span>General C</span>
        </div>
        <div class="leyenda-item">
            <div style="width: 14px; height: 14px; background-color: #607d8b; border-radius: 3px;"></div>
            <span>Camillero</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def show_forms():
    """Muestra los formularios para dar de alta nuevos pacientes y enfermeras"""
    st.markdown("---")
    st.markdown("## Dar de alta")

    # CORRECCIÓN: Verificar que habitaciones exista antes de acceder
    if 'habitaciones' not in st.session_state:
        st.error("No hay habitaciones cargadas. Por favor, recarga la página.")
        return

    # Variables separadas para cada formulario
    if 'nuevo_nombre_paciente' not in st.session_state:
        st.session_state.nuevo_nombre_paciente = ""
    if 'nuevo_expediente_paciente' not in st.session_state:
        st.session_state.nuevo_expediente_paciente = ""
    if 'nuevo_diagnostico_paciente' not in st.session_state:
        st.session_state.nuevo_diagnostico_paciente = CONFIG.DIAGNOSTICOS[0] if CONFIG.DIAGNOSTICOS else "Diagnóstico por definir"
    if 'habitacion_nuevo_paciente' not in st.session_state:
        habitaciones_disponibles_paciente = [hab for hab, datos in st.session_state.habitaciones.items()
                                           if len(datos.get('pacientes', [])) < get_maximo_pacientes_por_habitacion()]
        st.session_state.habitacion_nuevo_paciente = habitaciones_disponibles_paciente[0] if habitaciones_disponibles_paciente else ""

    if 'nuevo_nombre_enfermera' not in st.session_state:
        st.session_state.nuevo_nombre_enfermera = ""
  #  if 'nuevo_numero_economico_enfermera' not in st.session_state:
  #      st.session_state.nuevo_numero_economico_enfermera = ""
    if 'nuevo_rol_enfermera' not in st.session_state:
        st.session_state.nuevo_rol_enfermera = "General A"
    if 'habitacion_nuevo_enfermera' not in st.session_state:
        habitaciones_disponibles_enfermera = list(st.session_state.habitaciones.keys())
        st.session_state.habitacion_nuevo_enfermera = habitaciones_disponibles_enfermera[0] if habitaciones_disponibles_enfermera else ""

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Nuevo Paciente")

        habitaciones_disponibles_paciente = [hab for hab, datos in st.session_state.habitaciones.items()
                                          if len(datos.get('pacientes', [])) < get_maximo_pacientes_por_habitacion()]

        if not habitaciones_disponibles_paciente:
            st.warning("❌ No hay habitaciones disponibles para nuevos pacientes")
        else:
            with st.form(key="form_paciente", clear_on_submit=True):
                nombre_paciente = st.text_input(
                    "Nombre completo:",
                    value=st.session_state.nuevo_nombre_paciente,
                    key="input_nombre_paciente",
                    placeholder="Ingrese nombre del paciente"
                )

                expediente_paciente = st.text_input(
                    "Número de expediente:",
                    value=st.session_state.nuevo_expediente_paciente,
                    key="input_expediente_paciente",
                    placeholder="Ingrese número de expediente"
                )

                diagnostico_paciente = st.selectbox(
                    "Diagnóstico:",
                    options=CONFIG.DIAGNOSTICOS,
                    index=CONFIG.DIAGNOSTICOS.index(st.session_state.nuevo_diagnostico_paciente) if st.session_state.nuevo_diagnostico_paciente in CONFIG.DIAGNOSTICOS else 0,
                    key="select_diagnostico_paciente"
                )

                habitacion_paciente = st.selectbox(
                    "Habitación:",
                    options=habitaciones_disponibles_paciente,
                    index=habitaciones_disponibles_paciente.index(st.session_state.habitacion_nuevo_paciente) if st.session_state.habitacion_nuevo_paciente in habitaciones_disponibles_paciente else 0,
                    key="select_habitacion_paciente"
                )

                submitted_paciente = st.form_submit_button("Dar de alta paciente")

                if submitted_paciente:
                    st.session_state.nuevo_nombre_paciente = nombre_paciente
                    st.session_state.nuevo_expediente_paciente = expediente_paciente
                    st.session_state.nuevo_diagnostico_paciente = diagnostico_paciente
                    st.session_state.habitacion_nuevo_paciente = habitacion_paciente

                    if not nombre_paciente.strip():
                        st.error("❌ Por favor ingrese un nombre válido")
                    elif not expediente_paciente.strip():
                        st.error("❌ Por favor ingrese el número de expediente")
                    else:
                        st.session_state.tipo_nuevo = "paciente"
                        agregar_persona()

    with col2:
        st.markdown("### Nueva Enfermera")
        with st.form(key="form_enfermera", clear_on_submit=True):
            nombre_enfermera = st.text_input(
                "Nombre completo:",
                value=st.session_state.nuevo_nombre_enfermera,
                key="input_nombre_enfermera",
                placeholder="Ingrese nombre de la enfermera"
            )

            numero_economico_enfermera = st.text_input(
                "Número económico:",
                value=st.session_state.nuevo_numero_economico_enfermera,
                max_chars=10,
                key="input_numero_economico_enfermera",
                placeholder="Ingrese número económico"
            )

            habitacion_enfermera = st.selectbox(
                "Habitación:",
                list(st.session_state.habitaciones.keys()),
                index=list(st.session_state.habitaciones.keys()).index(st.session_state.habitacion_nuevo_enfermera) if st.session_state.habitacion_nuevo_enfermera in st.session_state.habitaciones else 0,
                key="select_habitacion_enfermera"
            )

            rol_enfermera = st.selectbox(
                "Rol:",
                ["Especialista", "General A", "General B", "General C", "Camillero"],
                index=["Especialista", "General A", "General B", "General C", "Camillero"].index(st.session_state.nuevo_rol_enfermera) if st.session_state.nuevo_rol_enfermera in ["Especialista", "General A", "General B", "General C", "Camillero"] else 1,
                key="select_rol_enfermera"
            )

            submitted_enfermera = st.form_submit_button("Dar de alta enfermera")

            if submitted_enfermera:
                st.session_state.nuevo_nombre_enfermera = nombre_enfermera
                st.session_state.nuevo_numero_economico_enfermera = numero_economico_enfermera
                st.session_state.habitacion_nuevo_enfermera = habitacion_enfermera
                st.session_state.nuevo_rol_enfermera = rol_enfermera

                if not nombre_enfermera.strip():
                    st.error("❌ Por favor ingrese un nombre válido")
                elif not numero_economico_enfermera.strip():
                    st.error("❌ Por favor ingrese el número económico")
                else:
                    st.session_state.tipo_nuevo = "enfermera"
                    agregar_persona()


# ====================
# FUNCIONES DE GESTIÓN PRINCIPAL (OPTIMIZADAS)
# ====================
def show_main_content():
    """Muestra el contenido principal de la aplicación"""

    # CORRECCIÓN: Verificar que habitaciones esté inicializado
    if 'habitaciones' not in st.session_state:
        st.error("No se han cargado las habitaciones. Por favor, recarga la página.")
        return

    if 'seleccion' not in st.session_state:
        st.session_state.seleccion = {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None}

    seleccion = st.session_state.get('seleccion', {"nombre": None, "tipo": None, "habitacion": None, "id": None, "diagnostico": None, "rol": None})

    show_estado_legend()

    if seleccion["nombre"]:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            if seleccion["tipo"] == "paciente":
                expediente_info = ""
                if seleccion["habitacion"] and seleccion["id"]:
                    habitacion_actual = seleccion["habitacion"]
                    persona_id = seleccion["id"]

                    if (habitacion_actual in st.session_state.habitaciones and
                        'pacientes' in st.session_state.habitaciones[habitacion_actual]):
                        for paciente in st.session_state.habitaciones[habitacion_actual]["pacientes"]:
                            if paciente["id"] == persona_id and "expediente" in paciente and paciente["expediente"]:
                                expediente_info = f"<div style='margin: 8px 0;'><b>Expediente:</b> {paciente['expediente']}</div>"
                                break

                st.markdown(f"""
                    <div class="seleccionado-box">
                        <div style="font-weight: bold; font-size: 1.1em;">{seleccion["nombre"]}</div>
                        <div style="margin: 8px 0;"><b>Diagnóstico:</b> {seleccion["diagnostico"]}</div>
                        {expediente_info}
                        <div><b>Habitación:</b> {seleccion["habitacion"]}</div>
                    </div>
                """, unsafe_allow_html=True)
            else:
                hora_entrada_info = ""
                if seleccion["habitacion"] and seleccion["id"]:
                    habitacion_actual = seleccion["habitacion"]
                    persona_id = seleccion["id"]

                    if (habitacion_actual in st.session_state.habitaciones and
                        'enfermeras' in st.session_state.habitaciones[habitacion_actual]):
                        for enfermera in st.session_state.habitaciones[habitacion_actual]["enfermeras"]:
                            if enfermera["id"] == persona_id and "hora_entrada" in enfermera:
                                hora_entrada_info = f"<div style='margin: 8px 0;'><b>Hora entrada:</b> {enfermera['hora_entrada']}</div>"
                                break

                st.markdown(f"""
                    <div class="seleccionado-box">
                        <div style="font-weight: bold; font-size: 1.1em;">{seleccion["nombre"]}</div>
                        <div style="margin: 8px 0;"><b>Rol:</b> {seleccion["rol"]}</div>
                        {hora_entrada_info}
                        <div><b>Habitación:</b> {seleccion["habitacion"]}</div>
                    </div>
                """, unsafe_allow_html=True)

        with col2:
            if st.button("🗑️ Borrar",
                        key=f"borrar_{seleccion['id']}",
                        use_container_width=True,
                        type="secondary"):
                if borrar_persona():
                    st.rerun()
                else:
                    st.error("❌ No se pudo eliminar la persona")

        with col3:
            if st.button("❌ Cancelar selección",
                        key=f"cancel_{seleccion['id']}",
                        use_container_width=True):
                st.session_state.seleccion = {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None}
                st.rerun()

    st.markdown("""
        <div style="background-color: #f0f8ff; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9em;">
            <b>Instrucciones:</b><br>
            1. Haz clic en un paciente o enfermera para seleccionarlo<br>
            2. Haz clic en "Mover aquí" de la habitación destino para trasladarlo<br>
            3. Haz clic en "Copiar aquí" para duplicar una enfermera en otra habitación<br>
            4. Haz clic en "Borrar" para eliminar la persona seleccionada<br>
            5. Usa los formularios abajo para dar de alta nuevos pacientes o enfermeras<br>
            6. <b>Nota:</b> Solo se muestran enfermeras que asistieron (sin incidencias)
        </div>
    """, unsafe_allow_html=True)

    # CORRECCIÓN: Ordenar habitaciones para mostrar consistentemente
    def ordenar_habitaciones_para_mostrar(hab_dict):
        """Ordena habitaciones por número de cama para mostrar"""
        def extraer_numero(hab_nombre):
            try:
                if "Cama" in hab_nombre:
                    return int(hab_nombre.split("Cama ")[1].strip())
                else:
                    return 0
            except:
                return 0

        return sorted(hab_dict.items(), key=lambda x: extraer_numero(x[0]))

    habitaciones_ordenadas = ordenar_habitaciones_para_mostrar(st.session_state.habitaciones)

    cols = st.columns(3)
    for i, (habitacion, datos) in enumerate(habitaciones_ordenadas):
        with cols[i % 3]:
            # CORRECCIÓN: Mostrar nombre de habitación sin servicio
            st.markdown(f"### {habitacion}")

            pacientes_count = len(datos.get('pacientes', []))
            enfermeras_count = len(datos.get('enfermeras', []))
            st.caption(f"{pacientes_count} paciente(s) • {enfermeras_count} enfermera(s)")

            for p in datos.get("pacientes", []):
                selected = (seleccion["id"] == p["id"])

                expediente_info = f"<div class='persona-info'>Expediente: {p.get('expediente', '')}</div>" if "expediente" in p and p.get('expediente') else ""

                container = st.container()
                with container:
                    st.markdown(f"""
                        <div class="persona-container" style="{'border: 2px solid #ffd54f; background-color: #fff8e1;' if selected else ''}">
                            <div class="persona-name">{p["nombre"]}</div>
                            <div class="persona-info">{p.get("diagnostico", "")}</div>
                            {expediente_info}
                            <div class="badge-container">
                                <div style="width: 0; height: 0; border-left: 8px solid transparent; border-right: 8px solid transparent; border-bottom: 14px solid {p.get("color", "#4caf50")};"></div>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                if container.button("",
                                 key=f"btn_p_{p['id']}",
                                 help=f"Seleccionar {p['nombre']}"):
                    if selected:
                        st.session_state.seleccion = {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None}
                    else:
                        st.session_state.seleccion = {
                            "id": p["id"],
                            "tipo": "paciente",
                            "nombre": p["nombre"],
                            "habitacion": habitacion,
                            "diagnostico": p.get("diagnostico", ""),
                            "rol": None
                        }
                    st.rerun()

            if datos.get("enfermeras"):
                st.markdown('<div class="seccion-enfermeras"><div class="seccion-enfermeras-title">Enfermeras asignadas</div></div>', unsafe_allow_html=True)

                for e in datos["enfermeras"]:
                    selected = (seleccion["id"] == e["id"])

                    container = st.container()
                    with container:
                        hora_info = f"<div class='persona-info'>Hora: {e.get('hora_entrada', 'No registrada')}</div>" if "hora_entrada" in e else ""

                        st.markdown(f"""
                            <div class="persona-container" style="{'border: 2px solid #ffd54f; background-color: #fff8e1;' if selected else ''}">
                                <div class="persona-name">{e["nombre"]}</div>
                                <div class="persona-info">{e.get("rol", "")}</div>
                                {hora_info}
                                <div class="badge-container">
                                    <div style="width: 14px; height: 14px; background-color: {e.get("color", "#9c27b0")}; border-radius: 3px;"></div>
                                </div>
                            </div>
                        """, unsafe_allow_html=True)

                    if container.button("",
                                     key=f"btn_e_{e['id']}",
                                     help=f"Seleccionar {e['nombre']}"):
                        if selected:
                            st.session_state.seleccion = {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None}
                        else:
                            st.session_state.seleccion = {
                                "id": e["id"],
                                "tipo": "enfermera",
                                "nombre": e["nombre"],
                                "habitacion": habitacion,
                                "diagnostico": None,
                                "rol": e.get("rol", "")
                            }
                        st.rerun()

            # CORRECCIÓN: Verificar disponibilidad antes de permitir mover
            if (seleccion["nombre"] and
                seleccion["habitacion"] and
                habitacion != seleccion["habitacion"]):

                tipo_seleccionado = "paciente" if seleccion["tipo"] == "paciente" else "enfermera"
                nombre_corto = seleccion["nombre"].split(": ")[1].split()[0] if ": " in seleccion["nombre"] else seleccion["nombre"]

                # CORRECCIÓN: Verificar que la cama destino esté disponible para pacientes
                if seleccion["tipo"] == "paciente":
                    pacientes_en_destino = len(datos.get('pacientes', []))
                    if pacientes_en_destino >= get_maximo_pacientes_por_habitacion():
                        st.error(f"❌ {habitacion} ya está ocupada")
                        continue

                if st.button(f"⇨ Mover {tipo_seleccionado} {nombre_corto} aquí",
                           key=f"mover_{habitacion}_{seleccion['id']}",
                           use_container_width=True):
                    mover_persona(habitacion)
                    st.rerun()

                if (seleccion["tipo"] == "enfermera" and
                    st.button(f"📋 Copiar {tipo_seleccionado} {nombre_corto} aquí",
                            key=f"copiar_{habitacion}_{seleccion['id']}",
                            use_container_width=True,
                            help="Crear una copia de esta enfermera en esta habitación")):
                    if copiar_enfermera_aqui(habitacion):
                        st.rerun()


# ====================
# FUNCIONES DE GESTIÓN DE PACIENTES/ENFERMERAS (OPTIMIZADAS)
# ====================
@synchronized("session_files")
def agregar_persona():
    """Agrega un nuevo paciente o enfermera según el formulario"""
    try:
        # CORRECCIÓN: Verificar que habitaciones esté inicializado
        if 'habitaciones' not in st.session_state:
            st.error("No hay habitaciones cargadas. No se puede agregar persona.")
            return False

        # CORRECCIÓN CRÍTICA: Usar variables temporales para evitar conflicto entre formularios
        if st.session_state.tipo_nuevo == "paciente":
            nombre_temp = st.session_state.get('nuevo_nombre_paciente', '')
            expediente_temp = st.session_state.get('nuevo_expediente_paciente', '')
            diagnostico_temp = st.session_state.get('nuevo_diagnostico_paciente', CONFIG.DIAGNOSTICOS[0] if CONFIG.DIAGNOSTICOS else "Diagnóstico por definir")
            habitacion_temp = st.session_state.get('habitacion_nuevo_paciente', '')

            if not nombre_temp.strip() or not expediente_temp.strip():
                st.warning("Por favor ingrese nombre y expediente válidos")
                return False

            # CORRECCIÓN: Verificar que la habitación exista
            if habitacion_temp not in st.session_state.habitaciones:
                st.error(f"La habitación {habitacion_temp} no existe")
                return False

            habitacion = habitacion_temp
            pacientes_actuales = len(st.session_state.habitaciones[habitacion].get("pacientes", []))

            # CORRECCIÓN CRÍTICA: Verificar que la cama esté disponible
            if pacientes_actuales >= get_maximo_pacientes_por_habitacion():
                st.error(f"❌ La habitación {habitacion} ya está al máximo de capacidad")
                return False

            nuevo_id = str(uuid.uuid4())

            numero_cama = "0"
            if "Cama" in habitacion:
                try:
                    numero_cama = habitacion.split("Cama ")[1].strip()
                except:
                    numero_cama = "0"

            nuevo_item = {
                "id": nuevo_id,
                "tipo": "paciente",
                "nombre": f"Pas: {nombre_temp}",
                "diagnostico": diagnostico_temp,
                "estado": "estable",
                "color": "#4caf50",
                "edad": 0,
                "fecha_ingreso": datetime.now().strftime("%Y-%m-%d"),
                "numero_cama": numero_cama,
                "expediente": expediente_temp
            }

        else:
            nombre_temp = st.session_state.get('nuevo_nombre_enfermera', '')
            numero_economico_temp = st.session_state.get('nuevo_numero_economico_enfermera', '')
            habitacion_temp = st.session_state.get('habitacion_nuevo_enfermera', '')
            rol_temp = st.session_state.get('nuevo_rol_enfermera', "General A")

            if not nombre_temp.strip() or not numero_economico_temp.strip():
                st.warning("Por favor ingrese nombre y número económico válidos")
                return False

            # CORRECCIÓN: Verificar que la habitación exista
            if habitacion_temp not in st.session_state.habitaciones:
                st.error(f"La habitación {habitacion_temp} no existe")
                return False

            numero_economico_clean = str(numero_economico_temp).strip()

            # ✅ OPTIMIZACIÓN: Verificación O(n) de duplicados
            numero_existente = False
            for habitacion, datos in st.session_state.habitaciones.items():
                for enfermera in datos.get("enfermeras", []):
                    if str(enfermera.get("numero_economico", "")).strip() == numero_economico_clean:
                        numero_existente = True
                        break
                if numero_existente:
                    break

            if numero_existente:
                st.error("❌ El número económico ya existe en la sesión actual. No se puede dar de alta.")
                return False

            nuevo_id = str(uuid.uuid4())

            numero_cama = "0"
            if "Cama" in habitacion_temp:
                try:
                    numero_cama = habitacion_temp.split("Cama ")[1].strip()
                except:
                    numero_cama = "0"

            colores_roles = {
                "Especialista": "#9c27b0",
                "General A": "#2196f3",
                "General B": "#ff9800",
                "General C": "#4caf50",
                "Camillero": "#607d8b"
            }

            nuevo_item = {
                "id": nuevo_id,
                "tipo": "enfermera",
                "nombre": f"Enf: {nombre_temp}",
                "rol": rol_temp,
                "color": colores_roles.get(rol_temp, "#9c27b0"),
                "numero_economico": numero_economico_clean,
                "hora_entrada": datetime.now().strftime("%H:%M"),
                "numero_cama": numero_cama
            }

        # AGREGAR A LA HABITACIÓN
        destino_lista = "pacientes" if st.session_state.tipo_nuevo == "paciente" else "enfermeras"
        st.session_state.habitaciones[habitacion_temp][destino_lista].append(nuevo_item)

        fecha_actual = datetime.now(pytz.timezone('America/Mexico_City'))
        fecha_formateada = fecha_actual.strftime("%y-%m-%d:%H:%M:%S")

        if 'log_movimientos' not in st.session_state:
            st.session_state.log_movimientos = []

        cama_destino = "0"
        if "Cama" in habitacion_temp:
            try:
                cama_destino = habitacion_temp.split("Cama ")[1].strip()
            except:
                cama_destino = habitacion_temp

        # Obtener el servicio del usuario autenticado
        servicio = st.session_state.user_data['servicio'] if 'user_data' in st.session_state else "SERVICIO"

        st.session_state.log_movimientos.insert(0, {
            "fecha": fecha_formateada,
            "tipo": st.session_state.tipo_nuevo,
            "nombre": nuevo_item["nombre"],
            "info": diagnostico_temp if st.session_state.tipo_nuevo == "paciente" else rol_temp,
            "desde": f"{servicio} - NUEVO",
            "hacia": f"Cama {cama_destino}",  # CORRECCIÓN: Sin servicio en el nombre
            "color": nuevo_item["color"],
            "estado": "alta",
            "id_persona": nuevo_id,
            "numero_economico": nuevo_item.get("numero_economico", "") if st.session_state.tipo_nuevo == "enfermera" else "",
            "expediente": nuevo_item.get("expediente", "") if st.session_state.tipo_nuevo == "paciente" else ""
        })

        # CORRECCIÓN CRÍTICA: Limpiar SOLO los campos específicos del tipo actual
        if st.session_state.tipo_nuevo == "paciente":
            st.session_state.nuevo_nombre_paciente = ""
            st.session_state.nuevo_expediente_paciente = ""
        else:
            st.session_state.nuevo_nombre_enfermera = ""
            st.session_state.nuevo_numero_economico_enfermera = ""

        st.success(f"✅ {st.session_state.tipo_nuevo.capitalize()} '{nombre_temp}' agregado exitosamente a {habitacion_temp}")

        # CORRECCIÓN CRÍTICA: Forzar rerun para actualizar la UI y limpiar formularios
        st.rerun()

        return True

    except Exception as e:
        st.error(f"❌ Error al agregar persona: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback: {traceback.format_exc()}")
        return False


@synchronized("session_files")
def borrar_persona():
    """Elimina la persona seleccionada (paciente o enfermera) del sistema"""
    if not st.session_state.seleccion:
        return False

    origen = st.session_state.seleccion["habitacion"]
    id_persona = st.session_state.seleccion["id"]
    tipo = st.session_state.seleccion["tipo"]
    nombre_persona = st.session_state.seleccion["nombre"]

    if origen in st.session_state.habitaciones:
        lista = st.session_state.habitaciones[origen]["pacientes"] if tipo == "paciente" else st.session_state.habitaciones[origen]["enfermeras"]

        persona_eliminada = None
        for idx, p in enumerate(lista):
            if p["id"] == id_persona:
                persona_eliminada = lista.pop(idx)
                break

        if persona_eliminada:
            fecha_actual = datetime.now(pytz.timezone('America/Mexico_City'))
            fecha_formateada = fecha_actual.strftime("%y-%m-%d:%H:%M:%S")

            if 'log_movimientos' not in st.session_state:
                st.session_state.log_movimientos = []

            cama_origen = "N/A"
            if "Cama" in origen:
                try:
                    cama_origen = origen.split("Cama ")[1].strip()
                except:
                    cama_origen = origen

            # Obtener el servicio del usuario autenticado
            servicio = st.session_state.user_data['servicio'] if 'user_data' in st.session_state else "SERVICIO"

            st.session_state.log_movimientos.insert(0, {
                "fecha": fecha_formateada,
                "tipo": tipo,
                "nombre": nombre_persona,
                "info": persona_eliminada["diagnostico"] if tipo == "paciente" else persona_eliminada.get("rol", ""),
                "desde": f"Cama {cama_origen}",  # CORRECCIÓN: Sin servicio en el nombre
                "hacia": f"{servicio} - ELIMINADO",
                "color": persona_eliminada["color"],
                "estado": "eliminado",
                "id_persona": persona_eliminada["id"],
                "numero_economico": persona_eliminada.get("numero_economico", "") if tipo == "enfermera" else "",
                "expediente": persona_eliminada.get("expediente", "") if tipo == "paciente" else ""
            })

            st.session_state.seleccion = {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None}
            return True

    return False

@synchronized("session_files")
def copiar_enfermera_aqui(habitacion_destino):
    """Copia la enfermera seleccionada a la habitación destino si no existe ya allí"""
    if not st.session_state.seleccion or st.session_state.seleccion["tipo"] != "enfermera":
        st.warning("❌ Primero selecciona una enfermera para copiar")
        return False

    origen = st.session_state.seleccion["habitacion"]
    id_enfermera = st.session_state.seleccion["id"]
    numero_economico = None

    enfermera_original = None
    if origen in st.session_state.habitaciones:
        for enfermera in st.session_state.habitaciones[origen]["enfermeras"]:
            if enfermera["id"] == id_enfermera:
                enfermera_original = enfermera.copy()
                numero_economico = enfermera.get('numero_economico')
                break

    if not enfermera_original:
        st.error("❌ No se encontró la enfermera seleccionada")
        return False

    # ✅ OPTIMIZACIÓN: Verificación rápida de duplicados
    if habitacion_destino in st.session_state.habitaciones and numero_economico:
        for enfermera in st.session_state.habitaciones[habitacion_destino]["enfermeras"]:
            if enfermera.get('numero_economico') == numero_economico:
                st.warning(f"⚠️ La enfermera {enfermera_original['nombre']} ya existe en {habitacion_destino}")

                fecha_actual = datetime.now(pytz.timezone('America/Mexico_City'))
                fecha_formateada = fecha_actual.strftime("%y-%m-%d:%H:%M:%S")

                if 'log_movimientos' not in st.session_state:
                    st.session_state.log_movimientos = []

                cama_origen = "N/A"
                cama_destino = "N/A"
                if "Cama" in origen:
                    try:
                        cama_origen = origen.split("Cama ")[1].strip()
                    except:
                        cama_origen = origen
                if "Cama" in habitacion_destino:
                    try:
                        cama_destino = habitacion_destino.split("Cama ")[1].strip()
                    except:
                        cama_destino = habitacion_destino

                # Obtener el servicio del usuario autenticado
                servicio = st.session_state.user_data['servicio'] if 'user_data' in st.session_state else "SERVICIO"

                st.session_state.log_movimientos.insert(0, {
                    "fecha": fecha_formateada,
                    "tipo": "enfermera",
                    "nombre": enfermera_original["nombre"],
                    "info": f"INTENTO_COPIA - Ya existe en destino",
                    "desde": f"Cama {cama_origen}",  # CORRECCIÓN: Sin servicio en el nombre
                    "hacia": f"Cama {cama_destino}",  # CORRECCIÓN: Sin servicio en el nombre
                    "color": "#ff0000",
                    "estado": "rechazado",
                    "id_persona": enfermera_original["id"],
                    "numero_economico": numero_economico
                })
                return False

    nueva_enfermera = enfermera_original.copy()
    nueva_enfermera["id"] = str(uuid.uuid4())
    nueva_enfermera["numero_economico"] = numero_economico

    if "Cama" in habitacion_destino:
        try:
            nueva_enfermera["numero_cama"] = habitacion_destino.split("Cama ")[1].strip()
        except:
            nueva_enfermera["numero_cama"] = "0"

    st.session_state.habitaciones[habitacion_destino]["enfermeras"].append(nueva_enfermera)

    fecha_actual = datetime.now(pytz.timezone('America/Mexico_City'))
    fecha_formateada = fecha_actual.strftime("%y-%m-%d:%H:%M:%S")

    if 'log_movimientos' not in st.session_state:
        st.session_state.log_movimientos = []

    cama_origen = "N/A"
    cama_destino = "N/A"
    if "Cama" in origen:
        try:
            cama_origen = origen.split("Cama ")[1].strip()
        except:
            cama_origen = origen
    if "Cama" in habitacion_destino:
        try:
            cama_destino = habitacion_destino.split("Cama ")[1].strip()
        except:
            cama_destino = habitacion_destino

    # Obtener el servicio del usuario autenticado
    servicio = st.session_state.user_data['servicio'] if 'user_data' in st.session_state else "SERVICIO"

    st.session_state.log_movimientos.insert(0, {
        "fecha": fecha_formateada,
        "tipo": "enfermera",
        "nombre": nueva_enfermera["nombre"],
        "info": f"COPIA - {nueva_enfermera.get('rol', '')}",
        "desde": f"Cama {cama_origen}",  # CORRECCIÓN: Sin servicio en el nombre
        "hacia": f"Cama {cama_destino}",  # CORRECCIÓN: Sin servicio en el nombre
        "color": nueva_enfermera["color"],
        "estado": "completado",
        "id_persona": nueva_enfermera["id"],
        "numero_economico": nueva_enfermera["numero_economico"]
    })

    st.session_state.seleccion = {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None}

    return True

@synchronized("session_files")
def mover_persona(habitacion_destino):
    """Move la persona seleccionada (paciente o enfermera) a la habitación destino"""
    if not st.session_state.seleccion:
        return

    origen = st.session_state.seleccion["habitacion"]
    id_persona = st.session_state.seleccion["id"]
    tipo = st.session_state.seleccion["tipo"]

    if origen and habitacion_destino != origen:
        # ✅ OPTIMIZACIÓN: Verificación rápida de duplicados para enfermeras
        if tipo == "enfermera":
            numero_economico = None
            for enfermera in st.session_state.habitaciones[origen]["enfermeras"]:
                if enfermera["id"] == id_persona:
                    numero_economico = enfermera.get('numero_economico')
                    break

            if numero_economico and habitacion_destino in st.session_state.habitaciones:
                for enfermera in st.session_state.habitaciones[habitacion_destino]["enfermeras"]:
                    if enfermera.get('numero_economico') == numero_economico:
                        st.warning(f"⚠️ Esta enfermera ya existe en {habitacion_destino}")
                        return

        # CORRECCIÓN CRÍTICA: Verificar disponibilidad para pacientes
        if tipo == "paciente":
            pacientes_en_destino = len(st.session_state.habitaciones[habitacion_destino].get('pacientes', []))
            if pacientes_en_destino >= get_maximo_pacientes_por_habitacion():
                st.error(f"❌ La habitación {habitacion_destino} ya está ocupada")
                return

        lista_origen = st.session_state.habitaciones[origen]["pacientes"] if tipo == "paciente" else st.session_state.habitaciones[origen]["enfermeras"]
        lista_destino = st.session_state.habitaciones[habitacion_destino]["pacientes"] if tipo == "paciente" else st.session_state.habitaciones[habitacion_destino]["enfermeras"]

        persona_movida = None
        for idx, p in enumerate(lista_origen):
            if p["id"] == id_persona:
                persona_movida = lista_origen.pop(idx)
                lista_destino.append(persona_movida)
                break

        if persona_movida:
            fecha_actual = datetime.now(pytz.timezone('America/Mexico_City'))
            fecha_formateada = fecha_actual.strftime("%y-%m-%d:%H:%M:%S")

            if 'log_movimientos' not in st.session_state:
                st.session_state.log_movimientos = []

            cama_destino = "N/A"
            if "Cama" in habitacion_destino:
                try:
                    cama_destino = habitacion_destino.split("Cama ")[1].strip()
                except:
                    cama_destino = habitacion_destino

            cama_origen = "N/A"
            if "Cama" in origen:
                try:
                    cama_origen = origen.split("Cama ")[1].strip()
                except:
                    cama_origen = origen

            # Obtener el servicio del usuario autenticado
            servicio = st.session_state.user_data['servicio'] if 'user_data' in st.session_state else "SERVICIO"

            st.session_state.log_movimientos.insert(0, {
                "fecha": fecha_formateada,
                "tipo": tipo,
                "nombre": persona_movida["nombre"],
                "info": persona_movida["diagnostico"] if tipo == "paciente" else persona_movida["rol"],
                "desde": f"Cama {cama_origen}",  # CORRECCIÓN: Sin servicio en el nombre
                "hacia": f"Cama {cama_destino}",  # CORRECCIÓN: Sin servicio en el nombre
                "color": persona_movida["color"],
                "estado": "completado",
                "id_persona": persona_movida["id"],
                "numero_economico": persona_movida.get("numero_economico", "") if tipo == "enfermera" else "",
                "expediente": persona_movida.get("expediente", "") if tipo == "paciente" else ""
            })

        st.session_state.seleccion = {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None}


# ====================
# FUNCIONES AUXILIARES
# ====================
def get_maximo_pacientes_por_habitacion():
    """Retorna el máximo número de pacientes permitidos por habitación"""
    return 1

def show_availability_info():
    """Muestra información de disponibilidad de habitaciones"""
    # CORRECCIÓN: Verificar que habitaciones exista
    if 'habitaciones' not in st.session_state:
        return

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📊 Disponibilidad")

    total_habitaciones = len(st.session_state.habitaciones)
    habitaciones_disponibles = len([hab for hab, datos in st.session_state.habitaciones.items()
                                  if len(datos.get('pacientes', [])) < get_maximo_pacientes_por_habitacion()])

    st.sidebar.info(f"**Habitaciones disponibles:** {habitaciones_disponibles}/{total_habitaciones}")

    for habitacion, datos in st.session_state.habitaciones.items():
        pacientes_count = len(datos.get('pacientes', []))
        capacidad = get_maximo_pacientes_por_habitacion()
        disponibilidad = capacidad - pacientes_count

        if disponibilidad > 0:
            st.sidebar.write(f"• {habitacion}: {disponibilidad} cama(s) disponible(s)")


@synchronized("log_files")
def guardar_log_transferencias(user_info):
    """Guarda el log de transferencias en el servidor SFTP con el NUEVO sistema de rutas"""
    if not st.session_state.get('log_movimientos', []):
        st.warning("No hay movimientos para guardar")
        return False

    st.info("📋 Movimientos pendientes por guardar:")
    for i, mov in enumerate(st.session_state.log_movimientos[:5]):
        estado = "✅" if mov.get("estado") in ["completado", "alta"] else "❌"
        destino = mov.get("hacia", mov.get("hacia", "N/A"))
        st.write(f"{estado} {mov['fecha']} - {mov['nombre']} -> {destino} ({mov.get('estado', 'completado')})")

    if st.button("💾 Confirmar y Guardar Log de Transferencias",
                key="btn_confirmar_guardar_log",
                use_container_width=True,
                help="Guarda el historial de movimientos en el servidor"):

        try:
            # NUEVO SISTEMA DE RUTAS: YYYY-MM-DD-HH-MM-SS-servicio.transferencias.csv
            timestamp_actual = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")
            filename = f"{timestamp_actual}-{user_info['servicio']}.transferencias.csv"
            
            # CORRECCIÓN: Ruta en directorio del usuario específico con número económico
            user_log_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_servicios", user_info['numero_economico'])
            remote_path = os.path.join(user_log_dir, filename)

            ssh = SSHManager.get_connection()
            if not ssh:
                st.error("❌ Error de conexión al servidor")
                return False

            try:
                sftp = ssh.open_sftp()
                
                # CORRECCIÓN: Asegurar que el directorio del usuario existe
                try:
                    sftp.listdir(user_log_dir)
                except FileNotFoundError:
                    SSHManager._create_remote_dirs(sftp, user_log_dir)
                    if CONFIG.DEBUG_MODE:
                        st.info(f"✅ Directorio creado: {user_log_dir}")
                
                # Verificar si el archivo existe
                archivo_existe = False
                try:
                    sftp.stat(remote_path)
                    archivo_existe = True
                    if CONFIG.DEBUG_MODE:
                        st.info(f"Archivo existente encontrado: {filename}")
                except FileNotFoundError:
                    archivo_existe = False
                    if CONFIG.DEBUG_MODE:
                        st.info(f"Creando nuevo archivo: {filename}")
                
            finally:
                if sftp:
                    try:
                        sftp.close()
                    except:
                        pass
                SSHManager.return_connection(ssh)

            # Construir contenido CSV como string
            csv_content = "fecha,tipo,nombre,info,desde,hacia,color,estado,id_persona,numero_economico,expediente\n"
            for mov in st.session_state.log_movimientos:
                fecha_formateada = mov["fecha"]
                estado = mov.get("estado", "completado")
                destino = mov.get("hacia", mov.get("hacia", "N/A"))
                id_persona = mov.get("id_persona", "")
                numero_economico = mov.get("numero_economico", "")
                expediente = mov.get("expediente", "")

                csv_content += f"{fecha_formateada},{mov['tipo']},{mov['nombre']},{mov['info']},{mov['desde']},{destino},{mov['color']},{estado},{id_persona},{numero_economico},{expediente}\n"

            if archivo_existe:
                success = agregar_contenido_a_archivo_remoto(remote_path, csv_content)
            else:
                success = SSHManager.put_remote_file(remote_path, csv_content)

            if success:
                accion = "actualizado" if archivo_existe else "creado"
                st.success(f"✅ Log {accion} correctamente: {filename}")
                st.info(f"📁 Ubicación: user_logs_servicios/{user_info['numero_economico']}/{filename}")
                st.session_state.log_movimientos = []
                return True
            else:
                st.error("❌ Error subiendo archivo al servidor")
                return False

        except Exception as e:
            st.error(f"❌ Error guardando log: {str(e)}")
            if CONFIG.DEBUG_MODE:
                st.error(f"Detalles del error: {type(e).__name__}")
                import traceback
                st.error(traceback.format_exc())
            return False
    else:
        st.info("👆 Haz clic en el botón para confirmar y guardar los movimientos")
        return False


@synchronized("log_files")
def reconstruir_desde_log(user_servicio, log_filename, user_info):
    """Reconstruye el estado actual aplicando las transferencias del log sobre la distribución original"""
    if CONFIG.DEBUG_MODE:
        st.info(f"Iniciando reconstrucción desde log: {log_filename}")

    # PRIMERO: Cargar los datos base de pacientes y enfermeras
    st.info("⏳ Cargando datos base de pacientes y enfermeras...")

    pacientes_df = load_csv_data_cached(CONFIG.FILES["pacientes"])
    enfermeras_df = load_csv_data_cached(CONFIG.FILES["enfermeras"])

    if pacientes_df is None or enfermeras_df is None:
        st.error("❌ No se pudieron cargar los archivos base necesarios")
        return None

    # Crear estructura inicial de habitaciones desde los datos base
    habitaciones = crear_estructura_habitaciones(user_servicio, pacientes_df, enfermeras_df)

    if not habitaciones:
        st.error("❌ No se pudo crear la estructura base de habitaciones")
        return None

    if CONFIG.DEBUG_MODE:
        total_pacientes_base = sum(len(h['pacientes']) for h in habitaciones.values())
        total_enfermeras_base = sum(len(h['enfermeras']) for h in habitaciones.values())
        st.info(f"✅ Estructura base creada: {len(habitaciones)} habitaciones, {total_pacientes_base} pacientes, {total_enfermeras_base} enfermeras")

    # SEGUNDO: Cargar y procesar el log seleccionado
    user_log_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_servicios", user_info['numero_economico'])
    user_log_path = os.path.join(user_log_dir, log_filename)

    log_content = SSHManager.get_remote_file(user_log_path)

    if not log_content:
        st.error(f"❌ No se pudo cargar el archivo log: {user_log_path}")
        return habitaciones  # Devolver al menos la estructura base

    try:
        # Convertir bytes a string si es necesario
        if isinstance(log_content, bytes):
            log_content = log_content.decode('utf-8')

        lines = log_content.strip().split('\n')
        if not lines or len(lines) <= 1:
            st.warning("⚠️ El archivo log está vacío o solo tiene encabezado. Usando distribución base.")
            return habitaciones

        header = lines[0].split(',')
        has_ids = 'id_persona' in [h.strip().lower() for h in header]

        if CONFIG.DEBUG_MODE:
            st.info(f"📋 Formato del log: {header}")
            st.info(f"🔑 Log tiene IDs: {has_ids}")
            st.info(f"📊 Total de líneas en log: {len(lines)}")

        # Estructuras para seguimiento
        ubicacion_actual_por_id = {}
        persona_por_id = {}

        # INICIALIZAR: Registrar todas las personas existentes en la estructura base
        for habitacion_nombre, datos_habitacion in habitaciones.items():
            for paciente in datos_habitacion.get("pacientes", []):
                if "id" in paciente:
                    ubicacion_actual_por_id[paciente["id"]] = habitacion_nombre
                    persona_por_id[paciente["id"]] = paciente

            for enfermera in datos_habitacion.get("enfermeras", []):
                if "id" in enfermera:
                    ubicacion_actual_por_id[enfermera["id"]] = habitacion_nombre
                    persona_por_id[enfermera["id"]] = enfermera

        lineas_procesadas = 0
        lineas_omitidas = 0
        eliminaciones_procesadas = 0
        altas_procesadas = 0
        movimientos_procesados = 0

        # CORRECCIÓN: Procesar líneas en orden cronológico (de más antiguo a más reciente)
        for line_num, line in enumerate(reversed(lines[1:]), 2):
            if not line.strip():
                continue

            parts = line.split(',')

            if CONFIG.DEBUG_MODE and line_num <= 5:
                st.info(f"🔍 Línea {line_num}: {parts[:8]}...")

            # CORRECCIÓN: Manejar diferentes formatos de CSV
            if has_ids and len(parts) >= 9:
                fecha = parts[0].strip() if len(parts) > 0 else ""
                tipo = parts[1].strip() if len(parts) > 1 else ""
                nombre = parts[2].strip() if len(parts) > 2 else ""
                info = parts[3].strip() if len(parts) > 3 else ""
                desde = parts[4].strip() if len(parts) > 4 else ""
                hacia = parts[5].strip() if len(parts) > 5 else ""
                color = parts[6].strip() if len(parts) > 6 else "#4caf50"
                estado = parts[7].strip() if len(parts) > 7 else "completado"
                id_persona = parts[8].strip() if len(parts) > 8 else str(uuid.uuid4())
                numero_economico = parts[9].strip() if len(parts) > 9 else ""
                expediente = parts[10].strip() if len(parts) > 10 else ""
            elif len(parts) >= 7:
                fecha = parts[0].strip() if len(parts) > 0 else ""
                tipo = parts[1].strip() if len(parts) > 1 else ""
                nombre = parts[2].strip() if len(parts) > 2 else ""
                info = parts[3].strip() if len(parts) > 3 else ""
                desde = parts[4].strip() if len(parts) > 4 else ""
                hacia = parts[5].strip() if len(parts) > 5 else ""
                color = parts[6].strip() if len(parts) > 6 else "#4caf50"
                estado = parts[7].strip() if len(parts) > 7 else "completado"
                id_persona = str(uuid.uuid4())
                numero_economico = ""
                expediente = ""
            else:
                if CONFIG.DEBUG_MODE:
                    st.warning(f"⚠️ Línea {line_num} ignorada (formato incorrecto)")
                lineas_omitidas += 1
                continue

            # Limpiar y validar valores
            estado = estado.strip().lower() if estado else "completado"
            desde = desde.strip() if desde else ""
            hacia = hacia.strip() if hacia else ""
            tipo = tipo.strip().lower() if tipo else ""

            if tipo not in ["paciente", "enfermera"]:
                if CONFIG.DEBUG_MODE:
                    st.warning(f"⚠️ Línea {line_num} ignorada (tipo inválido: {tipo})")
                lineas_omitidas += 1
                continue

            # Procesar ALTAS (nuevos pacientes/enfermeras)
            if estado == "alta" and "nuevo" in desde.lower():
                try:
                    # Extraer número de cama destino
                    cama_destino = "0"
                    if "cama" in hacia.lower():
                        try:
                            cama_destino = hacia.lower().split("cama ")[1].strip().split()[0]
                        except:
                            cama_destino = "0"
                    else:
                        numbers = re.findall(r'\d+', hacia)
                        if numbers:
                            cama_destino = numbers[0]

                    habitacion_destino_nombre = f"Cama {cama_destino}"

                    # Asegurar que existe la habitación destino
                    if habitacion_destino_nombre not in habitaciones:
                        habitaciones[habitacion_destino_nombre] = {"pacientes": [], "enfermeras": []}

                    # Crear nuevo item
                    if tipo == "paciente":
                        nuevo_item = {
                            "id": id_persona,
                            "tipo": "paciente",
                            "nombre": nombre,
                            "diagnostico": info,
                            "estado": "estable",
                            "color": color,
                            "edad": 0,
                            "fecha_ingreso": fecha.split(':')[0] if ':' in fecha else fecha,
                            "numero_cama": cama_destino,
                            "expediente": expediente
                        }
                        # Verificar que no exceda la capacidad
                        if len(habitaciones[habitacion_destino_nombre]["pacientes"]) < get_maximo_pacientes_por_habitacion():
                            habitaciones[habitacion_destino_nombre]["pacientes"].append(nuevo_item)
                        else:
                            st.warning(f"⚠️ No se pudo agregar paciente {nombre} - Cama {cama_destino} ocupada")
                            continue
                    else:
                        nuevo_item = {
                            "id": id_persona,
                            "tipo": "enfermera",
                            "nombre": nombre,
                            "rol": info,
                            "color": color,
                            "numero_economico": numero_economico,
                            "hora_entrada": ":".join(fecha.split(':')[-3:]) if ':' in fecha else "00:00",
                            "numero_cama": cama_destino
                        }
                        habitaciones[habitacion_destino_nombre]["enfermeras"].append(nuevo_item)

                    # Actualizar registros de seguimiento
                    ubicacion_actual_por_id[id_persona] = habitacion_destino_nombre
                    persona_por_id[id_persona] = nuevo_item

                    altas_procesadas += 1
                    lineas_procesadas += 1
                    if CONFIG.DEBUG_MODE:
                        st.info(f"✅ Alta procesada: {nombre} -> {habitacion_destino_nombre}")

                except Exception as e:
                    if CONFIG.DEBUG_MODE:
                        st.warning(f"Error procesando alta en línea {line_num}: {str(e)}")
                    lineas_omitidas += 1
                continue

            # Procesar ELIMINACIONES
            if "eliminado" in hacia.lower() or estado == "eliminado":
                if id_persona in persona_por_id:
                    ubicacion_actual = ubicacion_actual_por_id.get(id_persona)
                    if ubicacion_actual and ubicacion_actual in habitaciones:
                        lista_actual = habitaciones[ubicacion_actual]["pacientes"] if tipo == "paciente" else habitaciones[ubicacion_actual]["enfermeras"]
                        for idx, p in enumerate(lista_actual):
                            if p["id"] == id_persona:
                                lista_actual.pop(idx)
                                eliminaciones_procesadas += 1
                                if CONFIG.DEBUG_MODE:
                                    st.info(f"🗑️ Eliminación procesada: {nombre}")
                                # Limpiar registros
                                if id_persona in ubicacion_actual_por_id:
                                    del ubicacion_actual_por_id[id_persona]
                                if id_persona in persona_por_id:
                                    del persona_por_id[id_persona]
                                break
                continue

            # Procesar MOVIMIENTOS normales
            try:
                # Extraer números de cama
                cama_destino = "0"
                if "cama" in hacia.lower():
                    try:
                        cama_destino = hacia.lower().split("cama ")[1].strip().split()[0]
                    except:
                        cama_destino = "0"
                else:
                    numbers = re.findall(r'\d+', hacia)
                    if numbers:
                        cama_destino = numbers[0]

                cama_origen = "0"
                if "cama" in desde.lower():
                    try:
                        cama_origen = desde.lower().split("cama ")[1].strip().split()[0]
                    except:
                        cama_origen = "0"
                else:
                    numbers = re.findall(r'\d+', desde)
                    if numbers:
                        cama_origen = numbers[0]

                habitacion_destino_nombre = f"Cama {cama_destino}"
                habitacion_origen_nombre = f"Cama {cama_origen}"

                # Asegurar que existen las habitaciones
                if habitacion_destino_nombre not in habitaciones:
                    habitaciones[habitacion_destino_nombre] = {"pacientes": [], "enfermeras": []}
                if habitacion_origen_nombre not in habitaciones:
                    habitaciones[habitacion_origen_nombre] = {"pacientes": [], "enfermeras": []}

                # Buscar la persona
                persona_encontrada = None
                if id_persona in persona_por_id:
                    persona_encontrada = persona_por_id[id_persona]
                    ubicacion_actual = ubicacion_actual_por_id.get(id_persona)

                    # Remover de ubicación actual si es diferente
                    if ubicacion_actual and ubicacion_actual in habitaciones and ubicacion_actual != habitacion_destino_nombre:
                        lista_actual = habitaciones[ubicacion_actual]["pacientes"] if tipo == "paciente" else habitaciones[ubicacion_actual]["enfermeras"]
                        for idx, p in enumerate(lista_actual):
                            if p["id"] == id_persona:
                                lista_actual.pop(idx)
                                break

                # Si no se encuentra, puede ser una persona de la base que no estaba en el tracking
                if not persona_encontrada:
                    # Buscar en todas las habitaciones por nombre y tipo
                    for hab_nombre, hab_data in habitaciones.items():
                        lista_buscar = hab_data["pacientes"] if tipo == "paciente" else hab_data["enfermeras"]
                        for persona in lista_buscar:
                            if persona["nombre"] == nombre:
                                persona_encontrada = persona
                                ubicacion_actual_por_id[persona["id"]] = hab_nombre
                                persona_por_id[persona["id"]] = persona
                                # Remover de ubicación actual
                                lista_actual = habitaciones[hab_nombre]["pacientes"] if tipo == "paciente" else habitaciones[hab_nombre]["enfermeras"]
                                for idx, p in enumerate(lista_actual):
                                    if p["id"] == persona["id"]:
                                        lista_actual.pop(idx)
                                        break
                                break
                        if persona_encontrada:
                            break

                # Si aún no se encuentra, crear nueva persona
                if not persona_encontrada:
                    if tipo == "paciente":
                        persona_encontrada = {
                            "id": id_persona,
                            "tipo": "paciente",
                            "nombre": nombre,
                            "diagnostico": info,
                            "estado": "estable",
                            "color": color,
                            "edad": 0,
                            "fecha_ingreso": fecha.split(':')[0] if ':' in fecha else fecha,
                            "numero_cama": cama_destino,
                            "expediente": expediente
                        }
                    else:
                        persona_encontrada = {
                            "id": id_persona,
                            "tipo": "enfermera",
                            "nombre": nombre,
                            "rol": info,
                            "color": color,
                            "numero_economico": numero_economico,
                            "hora_entrada": ":".join(fecha.split(':')[-3:]) if ':' in fecha else "00:00",
                            "numero_cama": cama_destino
                        }

                    persona_por_id[id_persona] = persona_encontrada

                # Agregar a la habitación destino (verificar capacidad para pacientes)
                lista_destino = habitaciones[habitacion_destino_nombre]["pacientes"] if tipo == "paciente" else habitaciones[habitacion_destino_nombre]["enfermeras"]

                if tipo == "paciente" and len(lista_destino) >= get_maximo_pacientes_por_habitacion():
                    st.warning(f"⚠️ No se pudo mover paciente {nombre} - Cama {cama_destino} ocupada")
                    continue

                lista_destino.append(persona_encontrada)
                ubicacion_actual_por_id[id_persona] = habitacion_destino_nombre

                movimientos_procesados += 1
                lineas_procesadas += 1
                if CONFIG.DEBUG_MODE:
                    st.info(f"➡️ Movimiento procesado: {nombre} -> {habitacion_destino_nombre}")

            except Exception as e:
                if CONFIG.DEBUG_MODE:
                    st.warning(f"Error procesando movimiento en línea {line_num}: {str(e)}")
                lineas_omitidas += 1
                continue

        # ORDENAR habitaciones numéricamente
        def ordenar_habitaciones(hab_dict):
            def extraer_numero(hab_nombre):
                try:
                    if "Cama" in hab_nombre:
                        return int(hab_nombre.split("Cama ")[1].strip())
                    else:
                        return 0
                except:
                    return 0

            claves_ordenadas = sorted(hab_dict.keys(), key=extraer_numero)
            return {clave: hab_dict[clave] for clave in claves_ordenadas}

        habitaciones = ordenar_habitaciones(habitaciones)

        # Mostrar resumen final
        total_pacientes = sum(len(h['pacientes']) for h in habitaciones.values())
        total_enfermeras = sum(len(h['enfermeras']) for h in habitaciones.values())

        st.success(f"✅ Reconstrucción completada exitosamente")
        st.info(f"📊 Resumen final: {len(habitaciones)} habitaciones, {total_pacientes} pacientes, {total_enfermeras} enfermeras")
        st.info(f"📝 Procesamiento del log: {lineas_procesadas} líneas procesadas")
        st.info(f"   - {altas_procesadas} altas, {eliminaciones_procesadas} eliminaciones, {movimientos_procesados} movimientos, {lineas_omitidas} omitidas")

        return habitaciones

    except Exception as e:
        st.error(f"❌ Error procesando el log: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        # Devolver al menos la estructura base en caso de error
        return habitaciones

def show_summary(user_info):
    """Muestra el resumen de movimientos al final de la página"""
    st.markdown("""
    <div class="sumario-cambios">
        <h3>Historial de Movimientos</h3>
    """, unsafe_allow_html=True)

    if st.session_state.log_movimientos:
        for mov in st.session_state.log_movimientos[:10]:
            estado_icono = "✅" if mov.get("estado") in ["completado", "alta"] else "❌"
            estado_texto = f" ({mov.get('estado', 'completado')})" if mov.get("estado") else ""

            destino = mov.get("hacia", mov.get("hacia", "N/A"))

            st.markdown(f"""
                <div class="historial-item">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 3px;">
                        <span style="font-weight: bold; color: #666;">{estado_icono} {mov["fecha"]}{estado_texto}</span>
                        <div class="estado-badge" style="background-color: {mov["color"]};"></div>
                    </div>
                    <div style="font-weight: bold; margin: 3px 0;">{mov["nombre"]}</div>
                    <div style="font-size: 0.85em; color: #555; margin-bottom: 5px;">{mov["info"]}</div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.8em;">
                        <span style="color: #d32f2f;">{mov["desde"]}</span>
                        <span>→</span>
                        <span style="color: #388e3c;">{destino}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown(f"""
            <div style="margin-top: 15px; font-size: 0.9em;">
                <b>Total movimientos pendientes:</b> {len(st.session_state.log_movimientos)}<br>
                <b>Último movimiento:</b> {st.session_state.log_movimientos[0]["fecha"]}
            </div>
        """, unsafe_allow_html=True)

        guardar_log_transferencias(user_info)

    else:
        st.info("No hay movimientos registrados", icon="ℹ️")

    st.markdown("</div>", unsafe_allow_html=True)


# ====================
# FUNCIÓN PRINCIPAL (COMPLETA Y CORREGIDA)
# ====================
def main():
    """Función principal que ejecuta la aplicación"""
    try:
        setup_page_config()
        load_custom_styles()

        # CORRECCIÓN: Inicializar session_state.habitaciones PRIMERO
        if 'habitaciones' not in st.session_state:
            st.session_state.habitaciones = {}

        if 'auth_stage' not in st.session_state:
            st.session_state.auth_stage = 'numero_economico'

        if 'numero_economico' not in st.session_state:
            st.session_state.numero_economico = ''

        # Variables de sesión
        session_vars = {
            'seleccion': {"id": None, "tipo": None, "nombre": None, "habitacion": None, "diagnostico": None, "rol": None},
            'log_movimientos': [],
            # Variables separadas para formulario de pacientes
            'nuevo_nombre_paciente': "",
            'nuevo_expediente_paciente': "",
            'nuevo_diagnostico_paciente': CONFIG.DIAGNOSTICOS[0] if CONFIG.DIAGNOSTICOS else "Diagnóstico por definir",
            'habitacion_nuevo_paciente': "",
            # Variables separadas para formulario de enfermeras
            'nuevo_nombre_enfermera': "",
            'nuevo_numero_economico_enfermera': "",
            'nuevo_rol_enfermera': "General A",
            'habitacion_nuevo_enfermera': "",
            # Variable compartida para tipo de alta
            'tipo_nuevo': "",
            'session_cargada': False,
            'ultimo_inicio_jornada': None
        }

        for key, default_value in session_vars.items():
            if key not in st.session_state:
                st.session_state[key] = default_value

        authenticated, user_info = authenticate_user()
        if not authenticated:
            return

        show_logo()

        st.sidebar.success(f"Usuario: {user_info['nombre']}")
        st.sidebar.info(f"Servicio: {user_info['servicio']}")
        st.sidebar.info(f"Puesto: {user_info['puesto']}")
        st.sidebar.info(f"Turno laboral: {user_info['turno_laboral']}")
        st.sidebar.info(f"Fecha turno: {user_info['fecha_turno']}")

        # CORRECCIÓN: Inicializar habitaciones SIEMPRE después de la autenticación
        if not st.session_state.habitaciones:
            with st.spinner("🔄 Inicializando sistema y cargando datos..."):
                try:
                    initialize_session_state(user_info['servicio'], user_info)

                    # Verificar si la inicialización fue exitosa
                    if not st.session_state.habitaciones:
                        st.error(f"""
                        ❌ No se pudieron cargar las habitaciones.

                        **Posibles causas:**
                        - No hay datos para el servicio: **{user_info['servicio']}**
                        - No hay enfermeras para la fecha: **{user_info['fecha_turno']}** y turno: **{user_info['turno_laboral']}**
                        - Error de conexión con los archivos CSV

                        **Solución:**
                        1. Verifica que los archivos CSV tengan datos para tu servicio
                        2. Asegúrate de que la fecha y turno sean correctos
                        3. Intenta recargar la página
                        4. Contacta al administrador del sistema
                        """)

                        # Mostrar opción para recargar
                        if st.button("🔄 Recargar página"):
                            st.rerun()
                        return

                except Exception as e:
                    st.error(f"❌ Error durante la inicialización: {str(e)}")
                    if CONFIG.DEBUG_MODE:
                        import traceback
                        st.error(f"Detalles: {traceback.format_exc()}")

                    # Mostrar opción para recargar
                    if st.button("🔄 Recargar página"):
                        st.rerun()
                    return

        # CORRECCIÓN: Verificar que la inicialización fue exitosa antes de continuar
        if not st.session_state.habitaciones:
            st.error("❌ No se pudieron cargar las habitaciones. Por favor, recarga la página.")
            if st.button("🔄 Recargar página"):
                st.rerun()
            return

        manejar_inicio_jornada(user_info)
        show_availability_info()

        # CORRECCIÓN: Inicializar valores por defecto para formularios si es necesario
        if (not st.session_state.habitacion_nuevo_paciente or
            not st.session_state.habitacion_nuevo_enfermera) and st.session_state.habitaciones:

            habitaciones_list = list(st.session_state.habitaciones.keys())
            if habitaciones_list:
                if not st.session_state.habitacion_nuevo_paciente:
                    st.session_state.habitacion_nuevo_paciente = habitaciones_list[0]
                if not st.session_state.habitacion_nuevo_enfermera:
                    st.session_state.habitacion_nuevo_enfermera = habitaciones_list[0]

        if st.session_state.get('session_cargada', False):
            st.sidebar.info("📁 Sesión anterior cargada")
        else:
            st.sidebar.info("🆕 Nueva sesión iniciada")

        # CORRECCIÓN: Función de diagnóstico para debugging
        if CONFIG.DEBUG_MODE:
            st.sidebar.markdown("---")
            st.sidebar.markdown("### 🔍 Diagnóstico")

            if st.sidebar.button("Verificar datos fuente"):
                st.info("🔍 Verificando archivos de datos...")

                pacientes_df = load_csv_data_cached(CONFIG.FILES["pacientes"])
                enfermeras_df = load_csv_data_cached(CONFIG.FILES["enfermeras"])

                if pacientes_df is not None:
                    st.success(f"✅ Pacientes cargados: {len(pacientes_df)} registros")
                    st.info(f"Servicios únicos en pacientes: {list(pacientes_df['servicio'].unique())}")

                    # Mostrar pacientes del servicio actual
                    pacientes_servicio = pacientes_df[
                        pacientes_df['servicio'].str.strip().str.lower() == user_info['servicio'].lower()
                    ]
                    st.info(f"Pacientes en servicio actual: {len(pacientes_servicio)}")

                else:
                    st.error("❌ No se pudo cargar archivo de pacientes")

                if enfermeras_df is not None:
                    st.success(f"✅ Enfermeras cargadas: {len(enfermeras_df)} registros")
                    st.info(f"Servicios únicos en enfermeras: {list(enfermeras_df['servicio'].unique())}")
                    st.info(f"Fechas turno únicas: {list(enfermeras_df['fecha_turno'].unique())}")
                    st.info(f"Turnos laborales únicos: {list(enfermeras_df['turno_laboral'].unique())}")

                    # Mostrar enfermeras que cumplen los criterios
                    enfermeras_filtradas = enfermeras_df[
                        (enfermeras_df['servicio'].str.strip().str.lower() == user_info['servicio'].lower()) &
                        (enfermeras_df['fecha_turno'].astype(str).str.strip() == user_info['fecha_turno']) &
                        (enfermeras_df['turno_laboral'].str.strip().str.lower() == user_info['turno_laboral'].lower())
                    ]
                    st.info(f"Enfermeras que cumplen criterios: {len(enfermeras_filtradas)}")

                else:
                    st.error("❌ No se pudo cargar archivo de enfermeras")

        if CONFIG.DEBUG_MODE and 'habitaciones' in st.session_state:
            st.sidebar.markdown("---")
            st.sidebar.markdown("### 🔍 Verificación de Duplicados")

            if st.sidebar.button("Verificar duplicados", key="btn_verificar_duplicados"):
                duplicados = verificar_duplicados_enfermeras()
                if not duplicados:
                    st.sidebar.success("✅ No se encontraron duplicados")
                else:
                    st.sidebar.error(f"⚠️ {len(duplicados)} duplicados encontrados")

        st.sidebar.markdown("---")
        st.sidebar.markdown("### Gestión de Sesión")

        logs_disponibles = listar_logs_disponibles(user_info)
        if logs_disponibles:
            st.sidebar.markdown("#### 📋 Cargar desde histórico")
            log_seleccionado = st.sidebar.selectbox(
                "Seleccionar log para reconstruir:",
                logs_disponibles,
                format_func=lambda x: x.split('.')[0] + " - " + x.split('.')[1]
            )

            if st.sidebar.button("🔄 Reconstruir desde este log", use_container_width=True):
                with st.spinner("Reconstruyendo desde el log histórico..."):
                    habitaciones_reconstruidas = reconstruir_desde_log(user_info['servicio'], log_seleccionado, user_info)
                    if habitaciones_reconstruidas is not None:
                        st.session_state.habitaciones = habitaciones_reconstruidas
                        st.session_state.log_movimientos = []
                        st.session_state.session_cargada = True

                        if st.session_state.habitaciones:
                            habitaciones_list = list(st.session_state.habitaciones.keys())
                            if habitaciones_list:
                                st.session_state.habitacion_nuevo_paciente = habitaciones_list[0]
                                st.session_state.habitacion_nuevo_enfermera = habitaciones_list[0]

                        if CONFIG.DEBUG_MODE:
                            duplicados = verificar_duplicados_enfermeras()
                            if duplicados:
                                st.error("⚠️ Se encontraron duplicados después de reconstruir desde log")

                        st.success("✅ Estado reconstruido desde el log histórico")
                        st.rerun()
                    else:
                        st.error("❌ Error reconstruyendo desde el log")

        if st.sidebar.button("📋 Cargar distribución original", use_container_width=True):
            with st.spinner("Cargando distribución original..."):
                # Limpiar solo las variables necesarias
                keys_to_clear = ['habitaciones', 'log_movimientos', 'session_cargada', 'seleccion']
                for key in keys_to_clear:
                    if key in st.session_state:
                        del st.session_state[key]

                # Re-inicializar
                initialize_session_state(user_info['servicio'], user_info)

                if st.session_state.habitaciones:
                    habitaciones_list = list(st.session_state.habitaciones.keys())
                    if habitaciones_list:
                        st.session_state.habitacion_nuevo_paciente = habitaciones_list[0]
                        st.session_state.habitacion_nuevo_enfermera = habitaciones_list[0]

                    st.success("✅ Distribución original cargada")
                    st.rerun()
                else:
                    st.error("❌ Error al cargar datos originales")
                    if st.button("🔄 Recargar página"):
                        st.rerun()

        if st.sidebar.button("🚪 Salir y descartar cambios", use_container_width=True):
            with st.spinner("Limpiando sesión..."):
                keys_to_clear = list(st.session_state.keys())
                for key in keys_to_clear:
                    if key not in ['auth_stage', 'numero_economico']:  # Mantener info de autenticación
                        del st.session_state[key]

                # Reinicializar variables esenciales
                st.session_state.auth_stage = 'numero_economico'
                st.session_state.habitaciones = {}

                st.success("✅ Sesión limpiada exitosamente")
                st.rerun()

        # CORRECCIÓN: Mostrar información de debug si está habilitado
        if CONFIG.DEBUG_MODE:
            st.sidebar.markdown("---")
            st.sidebar.markdown("### 📊 Estado del Sistema")
            st.sidebar.info(f"Habitaciones cargadas: {len(st.session_state.habitaciones)}")
            if st.session_state.habitaciones:
                total_pacientes = sum(len(h['pacientes']) for h in st.session_state.habitaciones.values())
                total_enfermeras = sum(len(h['enfermeras']) for h in st.session_state.habitaciones.values())
                st.sidebar.info(f"Pacientes: {total_pacientes}, Enfermeras: {total_enfermeras}")

        # Mostrar contenido principal
        show_main_content()
        show_forms()
        show_summary(user_info)

        # CORRECCIÓN: Verificación de duplicados al final
        if CONFIG.DEBUG_MODE and st.session_state.habitaciones:
            duplicados = verificar_duplicados_enfermeras()
            if duplicados:
                st.error("⚠️ ADVERTENCIA: Se detectaron duplicados durante la ejecución")

                if st.button("🗑️ Eliminar duplicados automáticamente", key="btn_eliminar_duplicados_final"):
                    eliminar_duplicados_automaticamente(duplicados)
                    st.rerun()

    except Exception as e:
        st.error(f"Error crítico en la aplicación: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback: {traceback.format_exc()}")

        # Mostrar opción para recargar incluso en caso de error
        if st.button("🔄 Recargar página"):
            st.rerun()

    finally:
        try:
            CONNECTION_POOL.close_all_connections()
            if CONFIG.DEBUG_MODE:
                st.info("✓ Pool de conexiones limpiado exitosamente")
        except Exception as e:
            if CONFIG.DEBUG_MODE:
                st.error(f"Error limpiando pool de conexiones: {str(e)}")

if __name__ == "__main__":
    main()

# Agregar handler para cierre limpio al finalizar la aplicación
atexit.register(lambda: CONNECTION_POOL.close_all_connections())
