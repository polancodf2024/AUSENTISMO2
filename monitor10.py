import streamlit as st
from datetime import datetime
from PIL import Image
import os
import base64
from io import BytesIO
import uuid
import re
import pandas as pd
import paramiko
import csv
from io import StringIO
import tempfile
import pytz
import re
import json
import fcntl
import time
import hashlib
import threading
from collections import defaultdict
import socket

# ====================
# EXCEPCIONES PERSONALIZADAS
# ====================
class SecurityError(Exception):
    """Excepción para errores de seguridad"""
    pass

class RateLimitExceeded(Exception):
    """Excepción cuando se excede el límite de requests"""
    pass

class CircuitBreakerOpen(Exception):
    """Excepción cuando el circuit breaker está abierto"""
    pass

class LockTimeoutError(Exception):
    """Excepción cuando no se puede adquirir el lock"""
    pass

# ====================
# CONFIGURACIÓN INICIAL
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
            'TIMEOUT_SECONDS': 15
        }

        # File Configuration
        self.FILES = {
            "enfermeras": st.secrets["file_enfermeras2"],
            "claves": st.secrets["file_creacion_enfermeras2"],
            "pacientes": st.secrets["file_pacientes2"],
            # "suplencias": "aus_suplencias_activas2.csv"  # ARCHIVO COMENTADO
        }

        # Security Configuration
        self.MAX_REQUESTS_PER_MINUTE = st.secrets.get("max_requests_per_minute", 15)
        self.LOCK_TIMEOUT = st.secrets.get("lock_timeout", 15)
        self.CIRCUIT_BREAKER_THRESHOLD = st.secrets.get("circuit_breaker_threshold", 5)
        self.CIRCUIT_BREAKER_TIMEOUT = st.secrets.get("circuit_breaker_timeout", 30)

        # App Configuration
        self.SUPERVISOR_MODE = st.secrets.get("supervisor_mode", True)
        self.DEBUG_MODE = st.secrets.get("debug_mode", True)

CONFIG = Config()

# ====================
# SISTEMA DE SEGURIDAD
# ====================
class FileLock:
    @staticmethod
    def acquire_lock(filename, timeout=CONFIG.LOCK_TIMEOUT):
        """Adquiere lock para operaciones concurrentes"""
        lockfile = f"/tmp/{os.path.basename(filename)}.lock"
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                lock_fd = open(lockfile, 'w')
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if CONFIG.DEBUG_MODE:
                    st.info(f"🔒 Lock adquirido para: {filename}")
                return lock_fd
            except BlockingIOError:
                time.sleep(0.1)
            except Exception as e:
                if CONFIG.DEBUG_MODE:
                    st.error(f"Error adquiriendo lock: {str(e)}")
                break
        
        raise LockTimeoutError(f"No se pudo adquirir lock para {filename} después de {timeout} segundos")

    @staticmethod
    def release_lock(lock_fd, filename):
        """Libera lock"""
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
            if CONFIG.DEBUG_MODE:
                st.info(f"🔓 Lock liberado para: {filename}")
        except Exception as e:
            if CONFIG.DEBUG_MODE:
                st.error(f"Error liberando lock: {str(e)}")

class RateLimiter:
    def __init__(self, max_requests=CONFIG.MAX_REQUESTS_PER_MINUTE, time_window=60):
        self.requests = defaultdict(list)
        self.max_requests = max_requests
        self.time_window = time_window
        self.lock = threading.Lock()
    
    def check_limit(self, user_id):
        """Verifica si usuario excede límite de requests"""
        with self.lock:
            now = time.time()
            user_requests = self.requests[user_id]
            
            # Limpiar requests antiguos
            user_requests = [req for req in user_requests if now - req < self.time_window]
            self.requests[user_id] = user_requests
            
            if len(user_requests) >= self.max_requests:
                if CONFIG.DEBUG_MODE:
                    st.warning(f"⏰ Rate limit excedido para usuario: {user_id}")
                return False
            
            user_requests.append(now)
            return True

class CircuitBreaker:
    def __init__(self, failure_threshold=CONFIG.CIRCUIT_BREAKER_THRESHOLD, reset_timeout=CONFIG.CIRCUIT_BREAKER_TIMEOUT):
        self.failure_count = 0
        self.last_failure = 0
        self.threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.lock = threading.Lock()
    
    def allow_request(self):
        """Determina si permitir request"""
        with self.lock:
            if self.failure_count >= self.threshold:
                if time.time() - self.last_failure > self.reset_timeout:
                    self.reset()
                    if CONFIG.DEBUG_MODE:
                        st.info("🔌 Circuit breaker resetado")
                else:
                    if CONFIG.DEBUG_MODE:
                        st.warning("⚡ Circuit breaker abierto - Request bloqueado")
                    return False
            return True
    
    def record_failure(self):
        """Registra fallo"""
        with self.lock:
            self.failure_count += 1
            self.last_failure = time.time()
            if CONFIG.DEBUG_MODE:
                st.warning(f"🔴 Falla registrada - Contador: {self.failure_count}/{self.threshold}")
    
    def reset(self):
        """Resetea contador"""
        with self.lock:
            self.failure_count = 0
            if CONFIG.DEBUG_MODE:
                st.info("🟢 Circuit breaker resetado")

class ActivityMonitor:
    def __init__(self):
        self.active_operations = {}
        self.lock = threading.Lock()
    
    def start_operation(self, op_id, user_info, operation_type):
        """Registra inicio de operación"""
        with self.lock:
            self.active_operations[op_id] = {
                'user': user_info['numero_economico'],
                'user_name': user_info['nombre'],
                'start_time': time.time(),
                'operation_type': operation_type,
                'filename': None,
                'status': 'in_progress'
            }
            if CONFIG.DEBUG_MODE:
                st.info(f"📊 Operación iniciada: {op_id} - {operation_type}")
    
    def update_operation(self, op_id, filename=None, status=None):
        """Actualiza operación en curso"""
        with self.lock:
            if op_id in self.active_operations:
                if filename:
                    self.active_operations[op_id]['filename'] = filename
                if status:
                    self.active_operations[op_id]['status'] = status
    
    def end_operation(self, op_id, status='completed'):
        """Finaliza operación"""
        with self.lock:
            if op_id in self.active_operations:
                self.active_operations[op_id]['end_time'] = time.time()
                self.active_operations[op_id]['status'] = status
                duration = self.active_operations[op_id]['end_time'] - self.active_operations[op_id]['start_time']
                if CONFIG.DEBUG_MODE:
                    st.info(f"📊 Operación finalizada: {op_id} - Duración: {duration:.2f}s")
    
    def get_active_operations(self):
        """Obtiene operaciones activas"""
        with self.lock:
            return self.active_operations.copy()

# Instancias globales de seguridad
rate_limiter = RateLimiter()
circuit_breaker = CircuitBreaker()
activity_monitor = ActivityMonitor()

# ====================
# FUNCIONES DE UTILIDAD DE SEGURIDAD
# ====================

def sanitize_input(input_data, max_length=100):
    """Sanitiza entradas para prevenir inyección"""
    if not isinstance(input_data, str):
        return ""
    
    # Remover caracteres peligrosos
    sanitized = re.sub(r'[;|&$`<>{}]', '', input_data)
    # Limitar longitud
    return sanitized[:max_length].strip()

def verify_file_integrity(content, expected_hash=None):
    """Verifica integridad del archivo"""
    if not content:
        raise SecurityError("Contenido del archivo vacío")
    
    file_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    if expected_hash and file_hash != expected_hash:
        raise SecurityError("Integridad del archivo comprometida - Hash no coincide")
    
    return file_hash

def log_security_event(event_type, user_info, details, filename=None):
    """Registro de eventos de seguridad"""
    try:
        timestamp = datetime.now(pytz.timezone('America/Mexico_City')).isoformat()
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "user_id": user_info.get('numero_economico', 'unknown'),
            "user_name": user_info.get('nombre', 'unknown'),
            "ip": "N/A",  # Streamlit Cloud no expone IP directamente
            "filename": filename,
            "details": details
        }
        
        # Guardar en archivo seguro con locking
        lock = None
        try:
            lock = FileLock.acquire_lock("security_audit.log")
            with open("/tmp/security_audit.log", "a", encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        finally:
            if lock:
                FileLock.release_lock(lock, "security_audit.log")
                
    except Exception as e:
        if CONFIG.DEBUG_MODE:
            st.error(f"Error en log de seguridad: {str(e)}")

def retry_with_backoff(func, max_retries=3, base_delay=1, operation_id=None, user_info=None):
    """Reintento con backoff exponencial"""
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            if operation_id and user_info:
                activity_monitor.update_operation(operation_id, status=f"retry_attempt_{attempt+1}")
            return func()
        except Exception as e:
            last_exception = e
            if attempt == max_retries - 1:
                break
            delay = base_delay * (2 ** attempt)
            time.sleep(delay)
    
    if operation_id and user_info:
        log_security_event("retry_failed", user_info, 
                          f"Falló después de {max_retries} intentos: {str(last_exception)}")
    raise last_exception

def constant_time_compare(val1, val2):
    """Comparación en tiempo constante para prevenir timing attacks"""
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0

# ====================
# FUNCIONES SSH/SFTP MEJORADAS
# ====================
class SSHManager:
    @staticmethod
    def get_connection():
        """Establece conexión SSH segura con circuit breaker y reintentos"""
        if not circuit_breaker.allow_request():
            raise CircuitBreakerOpen("Servicio SFTP temporalmente no disponible")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        max_retries = 3
        retry_delay = 2  # segundos

        for attempt in range(max_retries):
            try:
                ssh.connect(
                    hostname=CONFIG.REMOTE['HOST'],
                    port=CONFIG.REMOTE['PORT'],
                    username=CONFIG.REMOTE['USER'],
                    password=CONFIG.REMOTE['PASSWORD'],
                    timeout=CONFIG.REMOTE['TIMEOUT_SECONDS'],
                    banner_timeout=30,
                    allow_agent=False,
                    look_for_keys=False
                )
                return ssh
            except paramiko.AuthenticationException:
                st.error("Error de autenticación SSH")
                circuit_breaker.record_failure()
                break
            except (paramiko.SSHException, socket.error, EOFError) as e:
                if attempt < max_retries - 1:
                    if CONFIG.DEBUG_MODE:
                        st.warning(f"Reintentando conexión SSH ({attempt + 1}/{max_retries})...")
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                else:
                    circuit_breaker.record_failure()
                    st.error(f"Error de conexión SSH después de {max_retries} intentos: {str(e)}")
                    return None
            except Exception as e:
                circuit_breaker.record_failure()
                st.error(f"Error inesperado en conexión SSH: {str(e)}")
                return None

        return None

    @staticmethod
    def get_remote_file(remote_filename, operation_id=None, user_info=None):
        """Lee archivo remoto con manejo de errores y seguridad mejorado"""
        if operation_id and user_info:
            activity_monitor.update_operation(operation_id, filename=remote_filename)

        ssh = SSHManager.get_connection()
        if not ssh:
            return None

        try:
            sftp = ssh.open_sftp()
            remote_path = os.path.join(CONFIG.REMOTE['DIR'], remote_filename)

            if CONFIG.DEBUG_MODE:
                st.info(f"Intentando leer archivo remoto: {remote_path}")

            # Adquirir lock para operación concurrente
            lock = FileLock.acquire_lock(remote_filename)
            try:
                # Verificar que el archivo existe antes de intentar leerlo
                try:
                    sftp.stat(remote_path)
                except FileNotFoundError:
                    st.error(f"Archivo no encontrado: {remote_path}")
                    return None

                with sftp.file(remote_path, 'r') as f:
                    content = f.read().decode('utf-8')

                # Verificar integridad del archivo
                verify_file_integrity(content)

                if CONFIG.DEBUG_MODE:
                    st.info(f"Archivo leído correctamente. Tamaño: {len(content)} bytes")

                return content
            finally:
                FileLock.release_lock(lock, remote_filename)
                sftp.close()
                ssh.close()

        except FileNotFoundError:
            st.error(f"Archivo no encontrado en servidor: {remote_filename}")
            log_security_event("file_not_found", user_info or {},
                             f"Archivo no encontrado: {remote_filename}", remote_filename)
            return None
        except SecurityError as e:
            st.error(f"Error de integridad en archivo: {str(e)}")
            log_security_event("file_integrity_error", user_info or {},
                             str(e), remote_filename)
            return None
        except Exception as e:
            st.error(f"Error leyendo archivo remoto: {str(e)}")
            circuit_breaker.record_failure()
            log_security_event("file_read_error", user_info or {},
                             str(e), remote_filename)
            return None
        finally:
            try:
                ssh.close()
            except:
                pass

    @staticmethod
    def put_remote_file(remote_path, content):
        """Escribe archivo remoto creando directorios si no existen con reintentos"""
        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            ssh = SSHManager.get_connection()
            if not ssh:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                return False

            try:
                sftp = ssh.open_sftp()

                # Extraer el directorio del path
                remote_dir = os.path.dirname(remote_path)

                # Crear directorios recursivamente si no existen
                try:
                    sftp.listdir(remote_dir)
                except (IOError, OSError):
                    try:
                        parent_dir = os.path.dirname(remote_dir)
                        if parent_dir and parent_dir != '/':
                            try:
                                sftp.listdir(parent_dir)
                            except (IOError, OSError):
                                SSHManager._create_remote_dirs(sftp, parent_dir)

                        sftp.mkdir(remote_dir)
                        if CONFIG.DEBUG_MODE:
                            st.info(f"Directorio creado: {remote_dir}")
                    except Exception as e:
                        st.error(f"Error creando directorio {remote_dir}: {str(e)}")
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay * (attempt + 1))
                            continue
                        return False

                # Crear archivo temporal
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp', encoding='utf-8') as temp_file:
                    temp_file.write(content)
                    temp_file_path = temp_file.name

                try:
                    sftp.put(temp_file_path, remote_path)
                    if CONFIG.DEBUG_MODE:
                        st.info(f"Archivo subido exitosamente: {remote_path}")
                    return True
                except Exception as e:
                    st.error(f"Error subiendo archivo al servidor: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * (attempt + 1))
                        continue
                    return False
                finally:
                    try:
                        os.unlink(temp_file_path)
                    except:
                        pass
            except Exception as e:
                st.error(f"Error en operación SFTP: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                return False
            finally:
                try:
                    sftp.close()
                    ssh.close()
                except:
                    pass

        return False

    @staticmethod
    def _create_remote_dirs(sftp, remote_dir):
        """Crea directorios remotos recursivamente"""
        try:
            sftp.stat(remote_dir)
        except FileNotFoundError:
            parent_dir = os.path.dirname(remote_dir)
            if parent_dir and parent_dir != '/':
                SSHManager._create_remote_dirs(sftp, parent_dir)
            sftp.mkdir(remote_dir)

# ====================
# FUNCIONES AUXILIARES
# ====================

def verificar_archivos_servidor(user_info):
    """Verifica que todos los archivos necesarios existan en el servidor con nombres alternativos"""
    archivos_requeridos = [
        CONFIG.FILES["enfermeras"],
        CONFIG.FILES["claves"],
        CONFIG.FILES["pacientes"]
    ]

    # Mapeo de nombres alternativos para búsqueda
    nombres_alternativos = {
        "aus_asistencia_enfermeras.csv": ["asistencia_enfermeras.csv", "enfermeras.csv", "personal.csv"]
    }

    for archivo in archivos_requeridos:
        contenido = SSHManager.get_remote_file(archivo, user_info=user_info)

        # Si no se encuentra el archivo principal, buscar nombres alternativos
        if contenido is None and archivo in nombres_alternativos:
            archivo_encontrado = False
            for nombre_alternativo in nombres_alternativos[archivo]:
                contenido_alt = SSHManager.get_remote_file(nombre_alternativo, user_info=user_info)
                if contenido_alt is not None:
                    st.warning(f"⚠️ Archivo {archivo} no encontrado, pero se encontró {nombre_alternativo}")
                    # Actualizar la configuración para usar el nombre correcto
                    if archivo == CONFIG.FILES["enfermeras"]:
                        CONFIG.FILES["enfermeras"] = nombre_alternativo
                    archivo_encontrado = True
                    break

            if not archivo_encontrado:
                st.warning(f"⚠️ Archivo {archivo} no encontrado en el servidor")
        elif contenido is None:
            st.warning(f"⚠️ Archivo {archivo} no encontrado en el servidor")
        elif CONFIG.DEBUG_MODE:
            st.info(f"✅ Archivo {archivo} encontrado en el servidor")

def incrementar_numero_consecutivo(user_info):
    """Incrementa el número consecutivo del usuario en el archivo de claves"""
    try:
        # Cargar el archivo de claves
        content = SSHManager.get_remote_file(CONFIG.FILES["claves"], user_info)
        if not content:
            st.error("No se pudo cargar el archivo de claves")
            return False

        # Convertir contenido a DataFrame
        claves_df = pd.read_csv(StringIO(content))

        # Limpiar y normalizar nombres de columnas
        claves_df.columns = claves_df.columns.str.strip().str.lower()

        # Asegurarse de que numero_economico sea string y esté limpio
        if 'numero_economico' in claves_df.columns:
            claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()

        # Buscar el usuario en el archivo de claves
        usuario_id_buscado = str(user_info['numero_economico']).strip()

        usuario_encontrado = claves_df[claves_df['numero_economico'] == usuario_id_buscado]

        if usuario_encontrado.empty:
            st.error(f"❌ Usuario {usuario_id_buscado} no encontrado en el archivo de claves")
            return False

        # Obtener el índice del usuario
        usuario_idx = usuario_encontrado.index[0]

        # Obtener y incrementar el número consecutivo
        numero_actual = int(claves_df.loc[usuario_idx, 'numero_consecutivo'])
        nuevo_numero = numero_actual + 1
        claves_df.loc[usuario_idx, 'numero_consecutivo'] = nuevo_numero

        # Convertir DataFrame a CSV
        csv_content = claves_df.to_csv(index=False)

        # Guardar el archivo actualizado
        remote_path = os.path.join(CONFIG.REMOTE['DIR'], CONFIG.FILES["claves"])
        success = SSHManager.put_remote_file(remote_path, csv_content)

        if success:
            st.success(f"✅ Número consecutivo incrementado: {numero_actual} → {nuevo_numero}")
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

def mover_logs_jornada_anterior(user_info):
    """Mueve los logs de la jornada anterior a la carpeta principal"""
    try:
        ssh = SSHManager.get_connection()
        if not ssh:
            st.error("❌ No se pudo conectar al servidor")
            return False

        sftp = ssh.open_sftp()

        # Directorio origen: carpeta específica del usuario
        user_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_supervision", user_info['numero_economico'])

        # Directorio destino: carpeta principal de logs
        main_log_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_supervision")

        try:
            # Verificar si existe el directorio del usuario
            sftp.stat(user_dir)

            # Listar todos los archivos en el directorio del usuario
            archivos = sftp.listdir(user_dir)

            if not archivos:
                st.info("📝 No hay archivos de log para mover")
                return True

            movidos_count = 0
            for archivo in archivos:
                origen_path = os.path.join(user_dir, archivo)
                destino_path = os.path.join(main_log_dir, archivo)

                # Mover el archivo
                try:
                    sftp.rename(origen_path, destino_path)
                    movidos_count += 1
                    if CONFIG.DEBUG_MODE:
                        st.info(f"📁 Movido: {archivo}")
                except Exception as e:
                    st.warning(f"⚠️ No se pudo mover {archivo}: {str(e)}")

            st.success(f"✅ Se movieron {movidos_count} archivos de log")
            return True

        except FileNotFoundError:
            st.info("📝 No existe directorio de usuario para mover logs")
            return True

        except Exception as e:
            st.error(f"❌ Error moviendo logs: {str(e)}")
            return False

        finally:
            sftp.close()
            ssh.close()

    except Exception as e:
        st.error(f"❌ Error en operación de mover logs: {str(e)}")
        return False

def load_csv_data(filename, user_info=None):
    """Carga datos desde un archivo CSV remoto con mejor manejo de errores"""
    operation_id = f"load_csv_{uuid.uuid4()}"
    if user_info:
        activity_monitor.start_operation(operation_id, user_info, f"load_csv_{filename}")

    try:
        # Verificar rate limiting
        user_id = user_info['numero_economico'] if user_info else 'anonymous'
        if not rate_limiter.check_limit(user_id):
            raise RateLimitExceeded("Demasiadas solicitudes en un período corto")

        if CONFIG.DEBUG_MODE:
            st.info(f"Cargando archivo: {filename}")

        # Reintento con backoff para operaciones de red
        def load_file():
            return SSHManager.get_remote_file(filename, operation_id, user_info)

        csv_content = retry_with_backoff(
            load_file,
            max_retries=3,
            base_delay=2,
            operation_id=operation_id,
            user_info=user_info
        )

        if not csv_content:
            st.error(f"No se pudo cargar el archivo {filename} después de varios intentos")
            activity_monitor.end_operation(operation_id, "failed")
            return None

        try:
            # Convertir a DataFrame con manejo de espacios y encoding
            df = pd.read_csv(StringIO(csv_content))

            # Limpiar espacios en nombres de columnas y normalizar a minúsculas
            df.columns = df.columns.str.strip().str.lower()

            # Limpiar espacios en blanco en todas las columnas de tipo string
            for col in df.columns:
                if df[col].dtype == 'object':
                    df[col] = df[col].astype(str).str.strip()

            if CONFIG.DEBUG_MODE:
                st.info(f"Archivo {filename} cargado correctamente. Filas: {len(df)}")

            activity_monitor.end_operation(operation_id, "completed")
            return df

        except Exception as e:
            st.error(f"Error procesando archivo {filename}: {str(e)}")
            log_security_event("csv_processing_error", user_info or {},
                             f"Error procesando {filename}: {str(e)}", filename)
            activity_monitor.end_operation(operation_id, "failed")
            return None

    except RateLimitExceeded as e:
        st.error("⏰ Demasiadas solicitudes. Por favor espere un momento.")
        log_security_event("rate_limit_exceeded", user_info or {},
                         f"Límite excedido para {filename}", filename)
        activity_monitor.end_operation(operation_id, "rate_limited")
        return None
    except Exception as e:
        st.error(f"Error inesperado cargando archivo: {str(e)}")
        activity_monitor.end_operation(operation_id, "failed")
        return None

def authenticate_user():
    """Autentica al usuario con medidas de seguridad mejoradas"""
    # Verificar rate limiting para autenticación
    if not rate_limiter.check_limit('auth_global'):
        st.error("⏰ Demasiados intentos de autenticación. Por favor espere.")
        return False, None

    st.title("🔐 Sistema de Supervisión Turno - Modo Registro")

    if 'auth_stage' not in st.session_state:
        st.session_state.auth_stage = 'numero_economico'
        st.session_state.auth_attempts = 0
        st.session_state.last_auth_attempt = 0

    # Prevenir brute force - tiempo de espera después de intentos fallidos
    current_time = time.time()
    if (st.session_state.auth_attempts >= 3 and
        current_time - st.session_state.last_auth_attempt < 300):  # 5 minutos de bloqueo
        st.error("🔒 Demasiados intentos fallidos. Espere 5 minutos antes de intentar nuevamente.")
        return False, None

    if 'numero_economico' not in st.session_state:
        st.session_state.numero_economico = ''

    if st.session_state.auth_stage == 'numero_economico':
        with st.form("auth_form_numero"):
            numero_economico = st.text_input("Número Económico", max_chars=10)
            numero_economico = sanitize_input(numero_economico)

            submitted = st.form_submit_button("Verificar")

            if submitted:
                st.session_state.last_auth_attempt = current_time
                st.session_state.auth_attempts += 1

                if not numero_economico:
                    st.error("Por favor ingrese su número económico")
                    return False, None

                st.session_state.numero_economico = numero_economico

                st.info(f"🔍 Verificando número económico: '{numero_economico}'")

                # Cargar archivos con medidas de seguridad
                enfermeras_df = load_csv_data(CONFIG.FILES["enfermeras"])
                claves_df = load_csv_data(CONFIG.FILES["claves"])

                if enfermeras_df is None or claves_df is None:
                    st.error("No se pudieron cargar los archivos necesarios para autenticación")
                    return False, None

                # Verificar columnas requeridas
                required_enfermeras = ['numero_economico', 'puesto', 'nombre_completo', 'incidencias', 'servicio', 'turno_laboral']
                for col in required_enfermeras:
                    if col not in enfermeras_df.columns:
                        st.error(f"❌ La columna '{col}' no existe en el archivo de enfermeras")
                        return False, None

                required_claves = ['numero_economico', 'password', 'turno_laboral']
                for col in required_claves:
                    if col not in claves_df.columns:
                        st.error(f"❌ La columna '{col}' no existe en el archivo de claves")
                        return False, None

                # Limpiar y verificar datos
                enfermeras_df['numero_economico'] = enfermeras_df['numero_economico'].astype(str).str.strip()
                claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
                numero_clean = numero_economico.strip()

                in_enfermeras = numero_clean in enfermeras_df['numero_economico'].values
                in_claves = numero_clean in claves_df['numero_economico'].values

                if not in_enfermeras or not in_claves:
                    st.error("❌ Número económico no registrado o sin permisos")
                    log_security_event("auth_failed", {},
                                     f"Número económico no encontrado: {numero_clean}")
                    return False, None

                # Obtener datos del usuario
                user_data = enfermeras_df[enfermeras_df['numero_economico'] == numero_clean].iloc[0]
                puesto = user_data['puesto'].strip().lower()
                servicio = user_data['servicio'].strip() if 'servicio' in user_data and not pd.isna(user_data['servicio']) else ""

                # Obtener turno laboral del archivo de enfermeras
                turno_laboral = user_data['turno_laboral'].strip() if 'turno_laboral' in user_data and not pd.isna(user_data['turno_laboral']) else ""

                # Obtener también del archivo de claves para verificar consistencia
                user_clave = claves_df[claves_df['numero_economico'] == numero_clean].iloc[0]
                turno_claves = user_clave['turno_laboral'].strip() if 'turno_laboral' in user_clave and not pd.isna(user_clave['turno_laboral']) else ""

                # Verificar que sea supervisión de turno
                if "supervision" not in puesto and "supervisión" not in puesto:
                    st.error("❌ Solo personal con puesto de supervisión puede acceder al sistema de transferencias")
                    log_security_event("auth_unauthorized", {},
                                     f"Intento de acceso no autorizado: {numero_clean} - Puesto: {puesto}")
                    return False, None

                # CORRECCIÓN: Verificar incidencias correctamente
                incidencias = user_data['incidencias']
                incidencias_str = str(incidencias).strip().upper() if not pd.isna(incidencias) else ""

                # Valores que indican que el usuario no asistió (SOLO códigos reales de incidencia)
                incidencias_invalidas = ['DS', 'VA', 'VR', 'VP', 'ON', 'DE', 'AC', 'BE', 'FE', 'CO', 'FA', 'SU', 'SL', 'IN', 'IG', 'CM', 'LC', 'LS', 'LI', 'NC']

                # "NO" NO es una incidencia válida, es solo un marcador de ausencia de incidencia
                if incidencias_str in incidencias_invalidas:
                    st.error("❌ Usuario con incidencias registradas. No puede acceder al sistema.")
                    log_security_event("auth_incidence", {},
                                     f"Usuario con incidencias: {numero_clean} - Incidencia: {incidencias_str}")
                    return False, None

                st.session_state.auth_stage = 'password'
                st.session_state.user_data = {
                    'numero_economico': numero_clean,
                    'nombre_completo': user_data['nombre_completo'],
                    'puesto': puesto,
                    'servicio': servicio,
                    'turno': turno_laboral
                }
                st.rerun()

    elif st.session_state.auth_stage == 'password':
        with st.form("auth_form_password"):
            st.info(f"Verificando usuario: {st.session_state.user_data['nombre_completo']}")
            st.info(f"Puesto: {st.session_state.user_data['puesto']}")
            st.info(f"Turno: {st.session_state.user_data['turno']}")

            password = st.text_input("Contraseña", type="password")
            confirm = st.form_submit_button("Validar Contraseña")

            if confirm:
                st.session_state.last_auth_attempt = current_time
                st.session_state.auth_attempts += 1

                if not password:
                    st.error("❌ Por favor ingrese su contraseña")
                    return False, None

                claves_df = load_csv_data(CONFIG.FILES["claves"])
                if claves_df is None:
                    st.error("No se pudo cargar el archivo de claves")
                    return False, None

                claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
                user_clave = claves_df[claves_df['numero_economico'] == st.session_state.numero_economico].iloc[0]

                # CORRECCIÓN: Verificar la contraseña correctamente
                stored_password = str(user_clave['password']).strip()
                
                # DEBUG: Mostrar información de la contraseña (solo en modo debug)
                if CONFIG.DEBUG_MODE:
                    st.info(f"🔍 Contraseña almacenada: '{stored_password}'")
                    st.info(f"🔍 Contraseña ingresada: '{password}'")
                    st.info(f"🔍 Coinciden: {stored_password == password}")

                # Comparación segura de contraseñas
                if not constant_time_compare(stored_password, password):
                    st.error("❌ Contraseña incorrecta")
                    log_security_event("auth_password_failed",
                                     {"numero_economico": st.session_state.numero_economico},
                                     "Contraseña incorrecta")
                    return False, None

                # Resetear contador de intentos en éxito
                st.session_state.auth_attempts = 0

                st.success("✅ Autenticación exitosa")
                log_security_event("auth_success",
                                 st.session_state.user_data,
                                 "Autenticación exitosa")
                st.session_state.auth_stage = 'authenticated'
                st.rerun()

    elif st.session_state.auth_stage == 'authenticated':
        return True, {
            'numero_economico': st.session_state.numero_economico,
            'nombre': st.session_state.user_data['nombre_completo'],
            'puesto': st.session_state.user_data['puesto'],
            'servicio': st.session_state.user_data['servicio'],
            'turno': st.session_state.user_data['turno']
        }

    return False, None

def obtener_servicios():
    """Devuelve la lista completa de servicios que deben mostrarse siempre"""
    return [
        "Dirección-Enfermería",
        "Consulta-Externa",
        "Diagnóstico",
        "CEyE-Hospitalización",
        "Unidad-Coronaria",
        "Hemodinámica",
        "3-piso",
        "Cardio-Neumología",
        "Nefrología",
        "CeyE-Quirúrgica",
        "SOP",
        "Perfusión",
        "TIC",
        "6-Piso",
        "7-Piso",
        "8-Piso",
        "9-Piso"
    ]


def filtrar_enfermeras_por_turno_servicio(enfermeras_df, user_turno, user_servicio, fecha_turno_usuario=None):
    """Filtra enfermeras por turno del usuario, fecha_turno y puestos válidos, NO por servicio"""
    if enfermeras_df is None or enfermeras_df.empty:
        return enfermeras_df

    # Limpiar y normalizar datos
    enfermeras_df.columns = enfermeras_df.columns.str.strip().str.lower()

    # DEBUG: Mostrar información del filtro
    if CONFIG.DEBUG_MODE:
        st.info(f"🔍 Filtrando enfermeras por turno: {user_turno}")
        st.info(f"🔍 Filtrando por fecha_turno: {fecha_turno_usuario}")
        st.info(f"📊 Total enfermeras antes de filtrar: {len(enfermeras_df)}")

    # FILTRAR POR FECHA_TURNO (si está disponible)
    enfermeras_filtradas = enfermeras_df.copy()

    if fecha_turno_usuario and 'fecha_turno' in enfermeras_filtradas.columns:
        # Convertir fecha_turno_usuario a string para comparación
        fecha_turno_str = fecha_turno_usuario.strftime("%Y-%m-%d") if hasattr(fecha_turno_usuario, 'strftime') else str(fecha_turno_usuario)

        enfermeras_filtradas = enfermeras_filtradas[
            enfermeras_filtradas['fecha_turno'].astype(str).str.strip() == fecha_turno_str
        ]

        if CONFIG.DEBUG_MODE:
            st.info(f"📊 Enfermeras después de filtrar por fecha_turno: {len(enfermeras_filtradas)}")

    # FILTRAR SOLO POR TURNO (filtro flexible) - NO FILTRAR POR SERVICIO
    if 'turno_laboral' in enfermeras_filtradas.columns:
        # Crear patrón de búsqueda flexible para el turno
        patron_turno = ""
        if "vespertino" in user_turno.lower():
            patron_turno = "Vespertino|14:30|1430|21:00|2100|14.30"
        elif "matutino" in user_turno.lower():
            patron_turno = "Matutino|7:00|0700|7.00|14:00|1400"
        elif "nocturno" in user_turno.lower():
            patron_turno = "Nocturno|21:00|2100|7:00|0700"
        else:
            # Si no reconocemos el turno, usar el texto exacto
            patron_turno = re.escape(user_turno)

        enfermeras_filtradas = enfermeras_filtradas[
            enfermeras_filtradas['turno_laboral'].str.strip().str.contains(patron_turno, case=False, na=False)
        ]

        if CONFIG.DEBUG_MODE:
            st.info(f"📊 Enfermeras después de filtrar por turno: {len(enfermeras_filtradas)}")

    return enfermeras_filtradas



def crear_estructura_habitaciones(user_servicio, pacientes_df, enfermeras_df, user_info, fecha_turno_usuario=None):
    """Crea la estructura completa de habitaciones con validación de datos y filtrado por turno y fecha_turno"""
    habitaciones = {}

    # Validar DataFrames
    if pacientes_df is None or enfermeras_df is None:
        return habitaciones

    # Filtrar enfermeras SOLO por turno, fecha_turno y puestos válidos, NO por servicio
    enfermeras_filtradas = filtrar_enfermeras_por_turno_servicio(
        enfermeras_df,
        user_info.get('turno', ''),
        None,  # ← No pasar el servicio para evitar el filtro
        fecha_turno_usuario  # ← Nueva: filtrar por fecha_turno
    )

    # Identificar la columna que contiene la hora de entrada
    posibles_nombres_hora = ['hora_entrada', 'hora entrada', 'entrada', 'hora', 'time', 'checkin']
    columna_hora_entrada = None

    for col in enfermeras_filtradas.columns:
        if any(nombre in col for nombre in posibles_nombres_hora):
            columna_hora_entrada = col
            break

    # Si no encontramos una columna específica, usar la sexta columna (índice 5)
    if columna_hora_entrada is None and len(enfermeras_filtradas.columns) >= 6:
        columna_hora_entrada = enfermeras_filtradas.columns[5]

    if columna_hora_entrada is None:
        st.error("No se pudo identificar la columna de hora de entrada")
        return habitaciones

    # Definir puestos válidos (los mismos que en la función de filtro)
    puestos_validos = [
        'enfermera general a', 'enfermera general b', 'enfermera general c',
        'enfermera especialista', 'ayudante general', 'camillero'
    ]

    # Filtrar enfermeras válidas (con hora de entrada válida - no vacía, no solo espacios, y NO "NO")
    if columna_hora_entrada:
        enfermeras_validas = enfermeras_filtradas[
            (~enfermeras_filtradas[columna_hora_entrada].isna()) &
            (enfermeras_filtradas[columna_hora_entrada].astype(str).apply(lambda x: not x.strip() == '')) &  # No vacío después de quitar espacios
            (enfermeras_filtradas[columna_hora_entrada].astype(str).apply(lambda x: x.strip().upper() != 'NO')) &  # Excluir "NO"
            (enfermeras_filtradas['puesto'].str.strip().str.lower().isin(puestos_validos))
        ]
    else:
        # Si no se pudo identificar la columna, usar todas las enfermeras (sin filtro de hora entrada)
        enfermeras_validas = enfermeras_filtradas[
            (enfermeras_filtradas['puesto'].str.strip().str.lower().isin(puestos_validos))
        ]

    # Obtener todos los servicios únicos de enfermeras válidas
    if 'servicio' in enfermeras_validas.columns:
        servicios_unicos = enfermeras_validas['servicio'].dropna().unique()
        for servicio in servicios_unicos:
            servicio_nombre = str(servicio).strip()
            if servicio_nombre and servicio_nombre not in habitaciones:
                habitaciones[servicio_nombre] = {
                    "pacientes": [],
                    "enfermeras": []
                }

    # Si no hay servicios en enfermeras, usar habitaciones de pacientes
    if not habitaciones and 'habitacion' in pacientes_df.columns:
        habitaciones_unicas = pacientes_df['habitacion'].dropna().unique()
        for habitacion in habitaciones_unicas:
            habitacion_nombre = str(habitacion).strip()
            if habitacion_nombre and habitacion_nombre not in habitaciones:
                habitaciones[habitacion_nombre] = {
                    "pacientes": [],
                    "enfermeras": []
                }

    # Asignar pacientes a habitaciones/servicios
    if 'habitacion' in pacientes_df.columns:
        for _, paciente in pacientes_df.iterrows():
            habitacion = str(paciente['habitacion']).strip() if not pd.isna(paciente['habitacion']) else ""
            servicio = str(paciente['servicio']).strip() if 'servicio' in paciente and not pd.isna(paciente['servicio']) else ""

            # Priorizar habitación, luego servicio
            destino = habitacion if habitacion and habitacion in habitaciones else servicio

            if destino and destino in habitaciones:
                # Sanitizar datos del paciente
                nombre_paciente = sanitize_input(paciente.get('nombre_completo', ''))
                diagnostico = sanitize_input(paciente.get('diagnostico', ''))

                habitaciones[destino]["pacientes"].append({
                    "nombre": nombre_paciente,
                    "tipo": "paciente",
                    "info": diagnostico,
                    "color": "#6a1b9a"
                })

    # Asignar enfermeras válidas a servicios
    for _, enfermera in enfermeras_validas.iterrows():
        servicio = str(enfermera['servicio'].strip()) if not pd.isna(enfermera['servicio']) else ""
        if servicio and servicio in habitaciones:
            puesto = enfermera['puesto'].strip().lower() if not pd.isna(enfermera['puesto']) else ""

            # Asignar color según el rol
            if 'general a' in puesto:
                color = "#4caf50"
                rol = "general-a"
            elif 'general b' in puesto:
                color = "#2196f3"
                rol = "general-b"
            elif 'general c' in puesto:
                color = "#9c27b0"
                rol = "general-c"
            elif 'camillero' in puesto:
                color = "#ff9800"
                rol = "camillero"
            elif 'ayudante' in puesto:
                color = "#ff9800"  # Mismo color que camillero
                rol = "ayudante"
            else:
                color = "#9c27b0"
                rol = "general-a"

            # Sanitizar datos de la enfermera
            nombre_enfermera = sanitize_input(enfermera.get('nombre_completo', ''))
            numero_economico = sanitize_input(str(enfermera.get('numero_economico', '')))
            hora_entrada_val = sanitize_input(str(enfermera.get(columna_hora_entrada, '')))

            habitaciones[servicio]["enfermeras"].append({
                "nombre": nombre_enfermera,
                "tipo": "enfermera",
                "info": rol,
                "color": color,
                "numero_economico": numero_economico,
                "hora_entrada": hora_entrada_val
            })

    return habitaciones


def mover_personal(servicio_destino, user_info):
    """Mueve el personal seleccionado al servicio destino con registro de seguridad"""
    origen = st.session_state.seleccion["servicio"]
    nombre = st.session_state.seleccion["nombre"]

    if origen and servicio_destino != origen:
        # Buscar y mover la enfermera
        encontrado = False
        for idx, p in enumerate(st.session_state.servicios[origen]):
            if p["nombre"] == nombre:
                profesional = st.session_state.servicios[origen].pop(idx)
                st.session_state.servicios[servicio_destino].append(profesional)
                encontrado = True

                # Registrar movimiento con timestamp seguro usando formato YY-MM-DD:HH:MM:SS
                fecha_actual = datetime.now(pytz.timezone('America/Mexico_City'))
                fecha_formateada = fecha_actual.strftime("%y-%m-%d:%H:%M:%S")

                st.session_state.log_movimientos.insert(0, {
                    "fecha": fecha_formateada,
                    "tipo": "enfermera",
                    "nombre": nombre,
                    "numero_economico": profesional["numero_economico"],
                    "info": profesional["rol"],
                    "desde": origen,
                    "hacia": servicio_destino,
                    "color": profesional["color"],
                    "estado": "completado"
                })

                # Log de seguridad
                log_security_event("personnel_moved", user_info,
                                 f"{nombre} movido de {origen} a {servicio_destino}")
                break

        if encontrado:
            st.session_state.seleccion = {"nombre": None, "servicio": None}
            st.rerun()
        else:
            st.error(f"No se encontró a {nombre} en {origen}")


def guardar_log_transferencias(user_info):
    """Guarda el log de transferencias en el servidor SFTP, añadiendo al archivo existente"""
    if not st.session_state.get('log_movimientos', []):
        st.warning("No hay movimientos para guardar")
        return False

    try:
        # Cargar el archivo de claves
        claves_df = load_csv_data(CONFIG.FILES["claves"], user_info)
        if claves_df is None:
            st.error("No se pudo cargar el archivo de claves")
            return False

        # Limpiar y normalizar nombres de columnas
        claves_df.columns = claves_df.columns.str.strip().str.lower()

        # Asegurarse de que numero_economico sea string y esté limpio
        if 'numero_economico' in claves_df.columns:
            claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()

        # Buscar el usuario en el archivo de claves
        usuario_id_buscado = str(user_info['numero_economico']).strip()

        if 'numero_economico' not in claves_df.columns:
            st.error("❌ La columna 'numero_economico' no existe en el archivo de claves")
            return False

        usuario_clave = claves_df[claves_df['numero_economico'] == usuario_id_buscado]

        if usuario_clave.empty:
            st.error(f"❌ Usuario {usuario_id_buscado} no encontrado en el archivo de claves")
            return False

        # Obtener turno laboral
        if 'turno_laboral' not in usuario_clave.columns:
            st.error("❌ La columna 'turno_laboral' no existe en el archivo de claves")
            return False

        turno_laboral = usuario_clave.iloc[0]['turno_laboral']
        if pd.isna(turno_laboral) or str(turno_laboral).strip() == '':
            st.error("❌ Turno laboral no asignado para este usuario")
            return False

        # CORRECCIÓN 1: Generar timestamp SIN brackets
        timestamp = datetime.now(pytz.timezone('America/Mexico_City')).strftime("%Y%m%d_%H%M%S_%f")

        # Limpiar caracteres problemáticos para el nombre de archivo
        turno_laboral = str(turno_laboral).strip().replace(" ", "_").replace("(", "").replace(")", "").replace(":", "")

        # CORRECCIÓN 1: Crear nombre del archivo SIN brackets
        filename = f"{timestamp}_{user_info['numero_economico']}_{turno_laboral}_movimientos.csv"

    except Exception as e:
        st.error(f"❌ Error obteniendo información del usuario: {str(e)}")
        return False

    # Mostrar confirmación al usuario
    st.info("📋 Movimientos pendientes por guardar:")
    for i, mov in enumerate(st.session_state.log_movimientos[:5]):
        estado = "✅" if mov.get("estado") in ["completado", "alta"] else "❌"
        destino = mov.get("hacia", mov.get("hacia", "N/A"))
        st.write(f"{estado} {mov['fecha']} - {mov['nombre']} -> {destino} ({mov.get('estado', 'completado')})")

    # Botón de confirmación
    if st.button("💾 Confirmar y Guardar Log de Transferencias",
                key="btn_confirmar_guardar_log",
                use_container_width=True,
                help="Guarda el historial de movimientos en el servidor"):

        try:
            # Construir path remoto en la carpeta user_logs_supervision
            user_log_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_supervision", user_info['numero_economico'])
            remote_path = os.path.join(user_log_dir, filename)

            # Crear directorio si no existe
            ssh = SSHManager.get_connection()
            if not ssh:
                st.error("❌ No se pudo conectar al servidor")
                return False

            sftp = ssh.open_sftp()
            try:
                sftp.stat(user_log_dir)
            except FileNotFoundError:
                # Crear directorio recursivamente
                try:
                    sftp.mkdir(user_log_dir)
                    if CONFIG.DEBUG_MODE:
                        st.info(f"📁 Directorio creado: {user_log_dir}")
                except Exception as e:
                    st.error(f"❌ Error creando directorio: {str(e)}")
                    return False

            # CORRECCIÓN 2: Crear contenido CSV manualmente SIN COMILLAS
            header = "fecha,tipo,nombre,numero_economico,info,desde,hacia,color,estado\n"
            lineas_csv = [header]

            for mov in st.session_state.log_movimientos:
                # Función para limpiar campos de caracteres problemáticos
                def limpiar_campo(campo):
                    if campo is None:
                        return ""
                    # Convertir a string y limpiar
                    campo_str = str(campo).strip()
                    # Remover comillas existentes y caracteres problemáticos del CSV
                    campo_str = campo_str.replace('"', '').replace("'", "").replace(',', ';')
                    # Remover saltos de línea y retornos de carro
                    campo_str = campo_str.replace('\n', ' ').replace('\r', ' ')
                    # Si después de limpiar está vacío, retornar N/A
                    return campo_str if campo_str else "N/A"

                fecha = limpiar_campo(mov["fecha"])
                tipo = limpiar_campo(mov['tipo'])
                nombre = limpiar_campo(mov['nombre'])
                numero_economico = limpiar_campo(mov.get('numero_economico', 'N/A'))
                info = limpiar_campo(mov['info'])
                desde = limpiar_campo(mov.get('desde', 'N/A'))
                hacia = limpiar_campo(mov.get('hacia', 'N/A'))
                color = limpiar_campo(mov['color'])
                estado = limpiar_campo(mov.get('estado', 'completado'))

                # Construir línea CSV manualmente SIN COMILLAS
                linea = f"{fecha},{tipo},{nombre},{numero_economico},{info},{desde},{hacia},{color},{estado}\n"
                lineas_csv.append(linea)

            # Unir todas las líneas
            csv_content = "".join(lineas_csv)

            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp', encoding='utf-8') as temp_file:
                temp_file.write(csv_content)
                temp_file_path = temp_file.name

            try:
                # Subir el archivo al servidor
                sftp.put(temp_file_path, remote_path)
                st.success(f"✅ Log guardado correctamente: {filename}")

                # Mostrar preview del contenido guardado
                if CONFIG.DEBUG_MODE:
                    st.info("📄 Contenido guardado (sin comillas):")
                    # Mostrar solo el header y las primeras 2 líneas de datos
                    lines = csv_content.strip().split('\n')[:3]
                    for line in lines:
                        st.code(line)

                # Contar líneas para información al usuario
                lineas_totales = len(csv_content.strip().split('\n')) - 1  # Restar el header
                lineas_nuevas = len(st.session_state.log_movimientos)
                st.info(f"📊 Total de movimientos guardados: {lineas_nuevas}")

                # Limpiar solo los movimientos actuales
                st.session_state.log_movimientos = []

                # Forzar recarga de la lista de logs
                st.rerun()

                return True
            except Exception as e:
                st.error(f"❌ Error subiendo archivo al servidor: {str(e)}")
                return False
            finally:
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                sftp.close()
                ssh.close()

        except Exception as e:
            st.error(f"❌ Error guardando log: {str(e)}")
            if CONFIG.DEBUG_MODE:
                import traceback
                st.error(f"Detalles del error: {traceback.format_exc()}")
            return False
    else:
        st.info("👆 Haz clic en el botón para confirmar y guardar los movimientos")
        return False


def listar_logs_disponibles(user_info):
    """Lista los archivos de log disponibles para este usuario con mejor manejo de errores"""
    try:
        ssh = SSHManager.get_connection()
        if not ssh:
            st.error("❌ No se pudo conectar al servidor para listar logs")
            return []

        sftp = ssh.open_sftp()
        user_log_dir = os.path.join(CONFIG.REMOTE['DIR'], "user_logs_supervision", user_info['numero_economico'])

        try:
            # Verificar si existe el directorio del usuario
            try:
                sftp.stat(user_log_dir)
                files = sftp.listdir(user_log_dir)

                if CONFIG.DEBUG_MODE:
                    st.info(f"📁 Directorio encontrado: {user_log_dir}")
                    st.info(f"📊 Archivos encontrados: {len(files)}")
                    for f in files:
                        st.info(f"   - {f}")

            except FileNotFoundError:
                if CONFIG.DEBUG_MODE:
                    st.info(f"📁 Directorio no encontrado: {user_log_dir}")
                files = []

        except Exception as e:
            if CONFIG.DEBUG_MODE:
                st.error(f"Error accediendo al directorio: {str(e)}")
            files = []
        finally:
            sftp.close()
            ssh.close()

        # Filtrar logs de movimientos del usuario específico
        movimientos_pattern = ".movimientos.csv"
        user_logs = [f for f in files if movimientos_pattern in f]

        if CONFIG.DEBUG_MODE:
            st.info(f"📊 Logs de movimientos encontrados: {len(user_logs)}")
            for log in user_logs:
                st.info(f"   - {log}")

        return sorted(user_logs, reverse=True)

    except Exception as e:
        if CONFIG.DEBUG_MODE:
            st.error(f"Error listando logs: {str(e)}")
        return []

def obtener_contenido_log(archivo_log, user_info):
    """Obtiene el contenido de un archivo de log específico"""
    try:
        user_log_path = os.path.join("user_logs_supervision", user_info['numero_economico'], archivo_log)
        contenido = SSHManager.get_remote_file(user_log_path, user_info=user_info)
        return contenido
    except Exception as e:
        st.error(f"Error leyendo archivo de log: {str(e)}")
        return None

def mostrar_contenido_log_tabular(contenido, nombre_archivo):
    """Muestra el contenido de un log en formato tabular simplificado"""
    if not contenido:
        st.warning("El archivo de log está vacío o no se pudo leer.")
        return

    st.markdown(f"### 📄 Contenido de: {nombre_archivo}")

    try:
        # Intentar cargar como CSV
        df = pd.read_csv(StringIO(contenido))

        # Ajustar la altura del dataframe según el número de registros
        height = min(400, max(200, len(df) * 35 + 40))  # Mínimo 200px, máximo 400px, ajustado por número de filas

        # Mostrar el dataframe sin estadísticas
        st.dataframe(df, use_container_width=True, height=height)

    except Exception as e:
        st.error(f"Error procesando el archivo de log: {str(e)}")
        st.text_area("Contenido del log (vista raw):", contenido, height=300)


def reconstruir_desde_log(user_servicio, log_filename, user_info):
    """Reconstruye el estado actual aplicando las transferencias del log sobre la distribución original, filtrando por turno"""

    # Cargar datos originales de enfermeras
    enfermeras_df = load_csv_data(CONFIG.FILES["enfermeras"], user_info)
    if enfermeras_df is None:
        st.error("No se pudieron cargar los datos de enfermeras")
        return None

    # OBTENER LA LISTA COMPLETA DE SERVICIOS (SIEMPRE MOSTRAR TODOS)
    servicios_completos = obtener_servicios()

    # Crear estructura inicial de servicios basada en el archivo original
    servicios = {}

    # Inicializar todos los servicios, incluso los vacíos
    for servicio_nombre in servicios_completos:
        servicios[servicio_nombre] = []

    # Limpiar y normalizar datos
    enfermeras_df.columns = enfermeras_df.columns.str.strip().str.lower()

    # OBTENER TURNO LABORAL DEL USUARIO ACTUAL para filtrar
    turno_usuario = user_info.get('turno', '').strip()

    # Si no tenemos turno del usuario, intentar obtenerlo del archivo de claves
    if not turno_usuario:
        claves_df = load_csv_data(CONFIG.FILES["claves"], user_info)
        if claves_df is not None and 'turno_laboral' in claves_df.columns:
            usuario_id = str(user_info['numero_economico']).strip()
            claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
            usuario_clave = claves_df[claves_df['numero_economico'] == usuario_id]
            if not usuario_clave.empty:
                turno_usuario = usuario_clave.iloc[0]['turno_laboral']
                user_info['turno'] = turno_usuario  # Actualizar user_info

    # Si aún no tenemos turno, usar vespertino por defecto
    if not turno_usuario:
        turno_usuario = "Vespertino (14:30-21:00)"
        user_info['turno'] = turno_usuario
        st.warning("⚠️ No se detectó turno del usuario, usando Vespertino por defecto")

    if CONFIG.DEBUG_MODE:
        st.info(f"🔍 Filtrando por turno: {turno_usuario}")
        st.info(f"📊 Total enfermeras antes de filtrar: {len(enfermeras_df)}")

    # OBTENER FECHA_TURNO DEL USUARIO ACTUAL
    fecha_turno_usuario = None
    if 'fecha_turno' in enfermeras_df.columns and user_info.get('numero_economico'):
        # Buscar la fecha_turno del usuario actual en el archivo
        usuario_id = str(user_info['numero_economico']).strip()
        enfermeras_df['numero_economico'] = enfermeras_df['numero_economico'].astype(str).str.strip()
        usuario_data = enfermeras_df[enfermeras_df['numero_economico'] == usuario_id]

        if not usuario_data.empty and 'fecha_turno' in usuario_data.columns:
            fecha_turno_usuario = usuario_data.iloc[0]['fecha_turno']
            if CONFIG.DEBUG_MODE:
                st.info(f"🔍 Fecha_turno del usuario encontrada: {fecha_turno_usuario}")

    # FILTRAR SOLO ENFERMERAS DEL TURNO Y FECHA_TURNO (NO por servicio)
    enfermeras_filtradas = filtrar_enfermeras_por_turno_servicio(
        enfermeras_df,
        turno_usuario,
        None,  # ← No filtrar por servicio
        fecha_turno_usuario  # ← Nueva: filtrar por fecha_turno
    )

    if CONFIG.DEBUG_MODE:
        st.info(f"📊 Enfermeras después de filtrar por turno y fecha_turno: {len(enfermeras_filtradas)}")

    # IDENTIFICAR COLUMNA DE HORA DE ENTRADA
    posibles_nombres_hora = ['hora_entrada', 'hora entrada', 'entrada', 'hora', 'time', 'checkin']
    columna_hora_entrada = None

    for col in enfermeras_filtradas.columns:
        if any(nombre in col for nombre in posibles_nombres_hora):
            columna_hora_entrada = col
            break

    # Si no encontramos una columna específica, usar la sexta columna (índice 5)
    if columna_hora_entrada is None and len(enfermeras_filtradas.columns) >= 6:
        columna_hora_entrada = enfermeras_filtradas.columns[5]

    # DEFINIR PUESTOS VÁLIDOS
    puestos_validos = [
        'enfermera general a', 'enfermera general b', 'enfermera general c',
        'enfermera especialista', 'ayudante general', 'camillero'
    ]

    # Filtrar enfermeras válidas (con hora de entrada válida)
    enfermeras_validas = enfermeras_filtradas.copy()

    if columna_hora_entrada:
        enfermeras_validas = enfermeras_validas[
            (~enfermeras_validas[columna_hora_entrada].isna()) &
            (enfermeras_validas[columna_hora_entrada].astype(str).apply(lambda x: not x.strip() == '')) &
            (enfermeras_validas[columna_hora_entrada].astype(str).apply(lambda x: x.strip().upper() != 'NO'))
        ]

    # Filtrar por puestos válidos
    if 'puesto' in enfermeras_validas.columns:
        enfermeras_validas = enfermeras_validas[
            enfermeras_validas['puesto'].str.strip().str.lower().isin(puestos_validos)
        ]

    if CONFIG.DEBUG_MODE:
        st.info(f"📊 Enfermeras válidas después de filtrar: {len(enfermeras_validas)}")

    # Agregar enfermeras válidas a sus servicios correspondientes
    for _, enfermera in enfermeras_validas.iterrows():
        servicio = str(enfermera.get('servicio', '')).strip()

        # Solo agregar si el servicio está en la lista completa
        if servicio and servicio in servicios:
            puesto = str(enfermera.get('puesto', '')).strip().lower()
            nombre = str(enfermera.get('nombre_completo', '')).strip()
            numero_economico = str(enfermera.get('numero_economico', '')).strip()

            # Asignar color según el rol
            if 'general a' in puesto:
                color = "#4caf50"
                rol = "general-a"
            elif 'general b' in puesto:
                color = "#2196f3"
                rol = "general-b"
            elif 'general c' in puesto:
                color = "#9c27b0"
                rol = "general-c"
            elif 'camillero' in puesto or 'ayudante' in puesto:
                color = "#ff9800"
                rol = "camillero"
            else:
                color = "#9c27b0"
                rol = "general-a"

            servicios[servicio].append({
                "nombre": nombre,
                "rol": rol,
                "color": color,
                "numero_economico": numero_economico,
                "hora_entrada": str(enfermera.get(columna_hora_entrada, '')) if columna_hora_entrada else ""
            })

    # DEBUG: Mostrar distribución inicial
    if CONFIG.DEBUG_MODE:
        st.info("📋 Distribución inicial (antes de aplicar log):")
        for servicio, personal in servicios.items():
            if personal:  # Solo mostrar servicios con personal
                st.write(f"{servicio}: {len(personal)} enfermeras")
                for p in personal:
                    st.write(f"  - {p['nombre']} ({p['numero_economico']}) - {p['rol']}")

    # Cargar el archivo log
    user_log_path = os.path.join("user_logs_supervision", user_info['numero_economico'], log_filename)
    log_content = SSHManager.get_remote_file(user_log_path, user_info=user_info)
    if not log_content:
        st.error("No se pudo cargar el archivo log")
        st.session_state.servicios = servicios
        return servicios

    # Procesar el log en orden cronológico (del más antiguo al más reciente)
    try:
        lines = log_content.strip().split('\n')
        if not lines:
            st.warning("El archivo de log está vacío")
            st.session_state.servicios = servicios
            return servicios

        header = lines[0]

        if CONFIG.DEBUG_MODE:
            st.info(f"📝 Procesando log con {len(lines)-1} movimientos")
            st.info(f"Header del log: {header}")

        # Determinar la estructura del archivo
        has_numero_economico = 'numero_economico' in header

        # Procesar movimientos en orden cronológico (del más antiguo al más reciente)
        movimientos_procesados = 0
        for line in lines[1:]:  # Saltar header
            if not line.strip():
                continue

            parts = line.split(',')
            if len(parts) < 7:
                continue

            if CONFIG.DEBUG_MODE:
                st.info(f"📄 Procesando línea: {line}")

            # Parsear campos según la versión del archivo
            if has_numero_economico and len(parts) >= 8:
                # Nuevo formato con numero_economico
                fecha, tipo, nombre, numero_economico, info, desde, hacia, color = parts[:8]
                estado = parts[8] if len(parts) > 8 else "completado"
            else:
                # Viejo formato sin numero_economico
                fecha, tipo, nombre, info, desde, hacia, color = parts[:7]
                numero_economico = "N/A"
                estado = parts[7] if len(parts) > 7 else "completado"

            # Solo procesar movimientos completados
            if estado.strip().lower() not in ["completado", "alta"]:
                continue

            desde = desde.strip()
            hacia = hacia.strip()
            nombre = nombre.strip()
            numero_economico = numero_economico.strip()

            if CONFIG.DEBUG_MODE:
                st.info(f"🔄 Movimiento: {nombre} de '{desde}' a '{hacia}'")

            # Buscar la enfermera por numero_economico (preferido) o por nombre
            enfermera_encontrada = None
            servicio_origen_obj = None

            # Primero buscar por numero_economico si está disponible y no es "N/A"
            if numero_economico and numero_economico != "N/A":
                for servicio_nombre, personal in servicios.items():
                    for idx, p in enumerate(personal):
                        if p.get("numero_economico", "") == numero_economico:
                            enfermera_encontrada = servicios[servicio_nombre].pop(idx)
                            servicio_origen_obj = servicio_nombre
                            if CONFIG.DEBUG_MODE:
                                st.info(f"✅ Encontrada por número económico: {nombre} en {servicio_origen_obj}")
                            break
                    if enfermera_encontrada:
                        break

            # Si no se encontró por numero_economico, buscar por nombre
            if not enfermera_encontrada:
                for servicio_nombre, personal in servicios.items():
                    for idx, p in enumerate(personal):
                        if p["nombre"] == nombre:
                            enfermera_encontrada = servicios[servicio_nombre].pop(idx)
                            servicio_origen_obj = servicio_nombre
                            if CONFIG.DEBUG_MODE:
                                st.info(f"✅ Encontrada por nombre: {nombre} en {servicio_origen_obj}")
                            break
                    if enfermera_encontrada:
                        break

            # Mover a la habitación destino si se encontró la enfermera
            if enfermera_encontrada and hacia in servicios:
                servicios[hacia].append(enfermera_encontrada)
                movimientos_procesados += 1
                if CONFIG.DEBUG_MODE:
                    st.success(f"📝 Movimiento aplicado: {nombre} de {servicio_origen_obj} a {hacia}")
            else:
                if CONFIG.DEBUG_MODE:
                    if not enfermera_encontrada:
                        st.warning(f"⚠️ No se encontró enfermera: {nombre} ({numero_economico})")
                    if hacia not in servicios:
                        st.warning(f"⚠️ Servicio destino no existe: {hacia}")

        if CONFIG.DEBUG_MODE:
            st.info(f"📊 Total movimientos procesados: {movimientos_procesados}")

        # DEBUG: Mostrar distribución final
        if CONFIG.DEBUG_MODE:
            st.info("📋 Distribución final (después de aplicar log):")
            for servicio, personal in servicios.items():
                if personal:  # Solo mostrar servicios con personal
                    st.write(f"{servicio}: {len(personal)} enfermeras")
                    for p in personal:
                        st.write(f"  - {p['nombre']} ({p['numero_economico']}) - {p['rol']}")

        # Actualizar el session_state con la distribución reconstruida
        st.session_state.servicios = servicios
        st.session_state.log_movimientos = []

        return servicios

    except Exception as e:
        st.error(f"Error procesando el log: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback: {traceback.format_exc()}")

        # En caso de error, mantener la distribución original
        st.session_state.servicios = servicios
        return servicios

def setup_page_config():
    """Configura la página de Streamlit"""
    st.set_page_config(
        layout="wide",
        page_title="Sistema de Supervisión Turno - Modo Registro",
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
        .servicio-container {
            border: 2px solid #4a8cff;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #f8fbff;
        }
        .servicio-header {
            font-size: 1.3em;
            font-weight: bold;
            color: #2c5fd1;
            margin-bottom: 15px;
            text-align: center;
        }
        .profesional-container {
            display: flex;
            align-items: center;
            padding: 10px;
            margin: 5px 0;
            background-color: white;
            border-radius: 5px;
            border: 1px solid #ddd;
        }
        .profesional-container:hover {
            background-color: #f0f6ff;
        }
        .selected {
            background-color: #fff8e1 !important;
            border: 2px solid #ffd54f !important;
        }
        .role-badge {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-left: auto;
        }
        .profesional-name {
            flex-grow: 1;
        }
        .historial-item {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 10px;
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
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .servicio-vacio {
            background-color: #f8f9fa;
            border: 2px dashed #ccc;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            margin-bottom: 20px;
            color: #666;
        }
        .servicio-vacio:hover {
            background-color: #e9ecef;
            border-color: #999;
        }
        </style>
    """, unsafe_allow_html=True)

def show_logo():
    """Muestra el título de la aplicación sin logo"""
    try:
        # Mostrar solo el título de la aplicación
        st.markdown(
            '<div style="text-align: center;"><h2>🏥 Supervisión de Enfermería por Turno</h2></div>',
            unsafe_allow_html=True
        )

        if CONFIG.DEBUG_MODE:
            st.info("✅ Título de la aplicación mostrado (logo removido)")

    except Exception as e:
        # Fallback en caso de error
        st.markdown(
            '<div style="text-align: center;"><h2>🏥 Supervisión de Enfermería por Turno</h2></div>',
            unsafe_allow_html=True
        )
        if CONFIG.DEBUG_MODE:
            st.error(f"Error mostrando título: {str(e)}")

def show_role_legend():
    """Muestra la leyenda de roles en la parte superior incluyendo suplentes"""
    st.markdown("""
    <div class="leyenda-horizontal">
        <div class="leyenda-item">
            <div class="role-badge" style="background-color: #ff5252;"></div>
            <span>Especialista</span>
        </div>
        <div class="leyenda-item">
            <div class="role-badge" style="background-color: #4caf50;"></div>
            <span>General-A</span>
        </div>
        <div class="leyenda-item">
            <div class="role-badge" style="background-color: #2196f3;"></div>
            <span>General-B</span>
        </div>
        <div class="leyenda-item">
            <div class="role-badge" style="background-color: #9c27b0;"></div>
            <span>General-C</span>
        </div>
        <div class="leyenda-item">
            <div class="role-badge" style="background-color: #ff9800;"></div>
            <span>Camillero</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

def show_main_content():
    """Muestra el contenido principal de la aplicación"""

    # Mostrar leyenda de roles en la parte superior
    show_role_legend()

    # Mostrar selección actual si hay alguna
    if st.session_state.seleccion["nombre"]:
        col1, col2 = st.columns([4, 1])
        with col1:
            st.markdown(f"""
                <div class="seleccionado-box">
                    <b>Profesional seleccionado:</b> {st.session_state.seleccion["nombre"]}
                </div>
            """, unsafe_allow_html=True)
        with col2:
            if st.button("❌ Cancelar selección", use_container_width=True):
                st.session_state.seleccion = {"nombre": None, "servicio": None}
                st.rerun()

    st.markdown("""
        <div style="background-color: #f0f8ff; padding: 10px; border-radius: 5px; margin-bottom: 20px; font-size: 0.9em;">
            <b>Instrucciones:</b><br>
            1. Haz clic en un profesional para seleccionarlo<br>
            2. Haz clic en "Mover aquí" del servicio destino<br>
            3. <strong>Todos los servicios se muestran, incluso los vacíos</strong> - puedes mover personal a servicios sin enfermeras
        </div>
    """, unsafe_allow_html=True)

    # Mostrar servicios en columnas - TODOS LOS SERVICIOS, INCLUYENDO VACÍOS
    cols = st.columns(3)
    
    # Obtener todos los servicios que deben mostrarse
    servicios_completos = obtener_servicios()
    
    for i, servicio in enumerate(servicios_completos):
        with cols[i % 3]:
            # Verificar si el servicio tiene enfermeras
            profesionales = st.session_state.servicios.get(servicio, [])
            
            if profesionales:
                # Servicio con enfermeras - mostrar normalmente
                st.markdown(f"### {servicio}")
                
                for idx, p in enumerate(profesionales):
                    selected = (st.session_state.seleccion["nombre"] == p["nombre"] and
                              st.session_state.seleccion["servicio"] == servicio)

                    # Contenedor clickeable para cada profesional
                    container = st.container()
                    with container:
                        col1, col2 = st.columns([4, 1])
                        with col1:
                            st.markdown(f'<div class="profesional-name">{p["nombre"]}</div>', unsafe_allow_html=True)
                        with col2:
                            st.markdown(f'<div class="role-badge" style="background-color: {p["color"]};"></div>', unsafe_allow_html=True)

                    # Crear clave única que incluya servicio, número económico e índice
                    key_unique = f"btn_{servicio}_{p['numero_economico']}_{idx}"
                    
                    # Manejar el clic en el contenedor
                    if container.button("", key=key_unique, help=p['nombre']):
                        if selected:
                            st.session_state.seleccion = {"nombre": None, "servicio": None}
                        else:
                            st.session_state.seleccion = {"nombre": p["nombre"], "servicio": servicio}
                        st.rerun()

                    # Aplicar estilo de selección
                    if selected:
                        st.markdown(
                            f"""
                            <style>
                                div[data-testid="stHorizontalBlock"] > div[data-testid="stVerticalBlock"] > div[data-testid="element-container"] > div[data-testid="stMarkdown"] > div[data-testid="stMarkdownContainer"] > div {{
                                    background-color: #fff8e1 !important;
                                    border: 2px solid #ffd54f !important;
                                }}
                            </style>
                            """,
                            unsafe_allow_html=True
                        )
            else:
                # Servicio vacío - mostrar con estilo especial
                st.markdown(f"""
                    <div class="servicio-vacio">
                        <h4>{servicio}</h4>
                        <p>🔄 Sin enfermeras asignadas</p>
                        <small>Puedes mover personal aquí</small>
                    </div>
                """, unsafe_allow_html=True)

            # Botón para mover al servicio actual (si hay una selección activa y no es el mismo servicio)
            if (st.session_state.seleccion["nombre"] and
                st.session_state.seleccion["servicio"] and
                servicio != st.session_state.seleccion["servicio"]):

                # Crear clave única para el botón de mover
                mover_key = f"mover_{servicio}_{st.session_state.seleccion['nombre'].replace(' ', '_')}"
                
                if st.button(f"Mover {st.session_state.seleccion['nombre'].split()[0]} aquí",
                           key=mover_key, use_container_width=True):
                    mover_personal(servicio, st.session_state.user_info)


def show_summary(user_info):
    """Muestra el resumen de movimientos con medidas de seguridad"""
    st.markdown("""
    <div class="sumario-cambios">
        <h3>Historial de Movimientos</h3>
    """, unsafe_allow_html=True)

    if st.session_state.log_movimientos:
        # Limitar la visualización a los últimos 10 movimientos por seguridad
        for mov in st.session_state.log_movimientos[:10]:
            estado_icono = "✅" if mov.get("estado") in ["completado", "alta"] else "❌"
            estado_texto = f" ({mov.get('estado', 'completado')})" if mov.get("estado") else ""

            # Mostrar numero_economico si está disponible
            info_extra = ""
            if mov.get("numero_economico") and mov.get("numero_economico") != "N/A":
                info_extra = f" | No. Econ: {mov['numero_economico']}"

            destino = mov.get("hacia", mov.get("hacia", "N/A"))

            st.markdown(f"""
                <div class="historial-item">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 3px;">
                        <span style="font-weight: bold; color: #666;">{estado_icono} {mov["fecha"]}{estado_texto}</span>
                        <div class="estado-badge" style="background-color: {mov["color"]};"></div>
                    </div>
                    <div style="font-weight: bold; margin: 3px 0;">{mov["nombre"]}{info_extra}</div>
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
                <b>Total movimientos:</b> {len(st.session_state.log_movimientos)}<br>
                <b>Último movimiento:</b> {st.session_state.log_movimientos[0]["fecha"]}
            </div>
        """, unsafe_allow_html=True)

        # Llamar a la función de guardado (solo se ejecuta si el usuario confirma)
        guardar_log_transferencias(user_info)

    else:
        st.info("No hay movimientos registrados", icon="ℹ️")

    st.markdown("</div>", unsafe_allow_html=True)

def manejar_inicio_jornada(user_info):
    """Maneja la pregunta de inicio de jornada laboral"""
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🏥 Inicio de Jornada")
    
    # Verificar si ya se respondió hoy
    hoy = datetime.now().strftime("%Y-%m-%d")
    if 'ultimo_inicio_jornada' in st.session_state and st.session_state.ultimo_inicio_jornada == hoy:
        st.sidebar.info("✅ Jornada ya iniciada hoy")
        return
    
    respuesta = st.sidebar.radio(
        "¿Estás iniciando tu jornada laboral?",
        ["No", "Sí"],
        index=0,
        key="inicio_jornada_radio"
    )
    
    if respuesta == "Sí":
        if st.sidebar.button("🔒 Confirmar Inicio de Jornada", use_container_width=True, key="btn_confirmar_jornada"):
            with st.spinner("Procesando inicio de jornada..."):
                try:
                    # 1. Primero mover logs de jornada anterior
                    if mover_logs_jornada_anterior(user_info):
                        # 2. Luego incrementar número consecutivo
                        if True:
                            #incrementar_numero_consecutivo(user_info):
                            # 3. FINALMENTE: Limpiar session_state y recargar distribución ORIGINAL
                            
                            # Guardar información del usuario antes de limpiar
                            user_info_backup = st.session_state.user_info.copy() if 'user_info' in st.session_state else user_info
                            user_servicio_backup = st.session_state.user_servicio if 'user_servicio' in st.session_state else user_info.get('servicio', '')
                            
                            # Limpiar completamente la sesión
                            keys_to_keep = ['auth_stage', 'auth_attempts', 'last_auth_attempt', 'numero_economico', 'user_data']
                            new_session_state = {}
                            
                            for key in keys_to_keep:
                                if key in st.session_state:
                                    new_session_state[key] = st.session_state[key]
                            
                            # Limpiar session_state
                            st.session_state.clear()
                            
                            # Restaurar keys necesarias
                            for key, value in new_session_state.items():
                                st.session_state[key] = value
                            
                            # Marcar jornada iniciada
                            st.session_state.ultimo_inicio_jornada = hoy
                            
                            # Recargar distribución ORIGINAL desde archivos remotos
                            with st.spinner("Cargando distribución original..."):
                                # Forzar recarga de datos
                                enfermeras_df = load_csv_data(CONFIG.FILES["enfermeras"], user_info)
                                claves_df = load_csv_data(CONFIG.FILES["claves"], user_info)
                                
                                if enfermeras_df is not None and claves_df is not None:
                                    # Re-inicializar session_state con datos originales
                                    initialize_session_state(user_servicio_backup, user_info_backup)
                                    
                                    st.sidebar.success("🎉 Jornada iniciada correctamente")
                                    st.sidebar.info("📁 Logs de jornadas anteriores movidos y distribución original cargada")
                                    log_security_event("jornada_iniciada", user_info, 
                                                     "Jornada laboral iniciada - Número consecutivo incrementado, logs movidos y distribución original cargada")
                                    
                                    # Forzar rerun para mostrar la distribución original
                                    st.rerun()
                                else:
                                    st.sidebar.error("❌ Error al cargar la distribución original")
                        else:
                            st.sidebar.error("❌ Error al incrementar número consecutivo")
                    else:
                        st.sidebar.error("❌ Error moviendo logs de jornada anterior")
                        
                except Exception as e:
                    st.sidebar.error(f"❌ Error al iniciar jornada: {str(e)}")
                    if CONFIG.DEBUG_MODE:
                        import traceback
                        st.sidebar.error(f"Detalles: {traceback.format_exc()}")
    else:
        st.sidebar.info("➡️ Continuando con sesión actual")

def generate_configuration_pdf(user_info):
    """Genera un PDF con la distribución actual de personal por servicio para supervisión de turno"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        from io import BytesIO
        import pytz
        from datetime import datetime

        # Crear buffer para el PDF
        buffer = BytesIO()

        # Configurar documento
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)

        # Estilos
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Center', alignment=TA_CENTER))
        styles.add(ParagraphStyle(name='Small', parent=styles['BodyText'], fontSize=8))
        styles.add(ParagraphStyle(name='Bold', parent=styles['BodyText'], fontName='Helvetica-Bold'))

        # Elementos del documento
        elements = []

        # Encabezado
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=TA_CENTER
        )

        elements.append(Paragraph("DISTRIBUCIÓN DE PERSONAL - SUPERVISIÓN DE TURNO", title_style))
        elements.append(Paragraph(f"Turno: {user_info.get('turno', 'N/A')}", styles['Heading2']))
        elements.append(Paragraph(f"Generado por: {user_info['nombre']} ({user_info['puesto']})", styles['BodyText']))
        elements.append(Paragraph(f"Fecha: {datetime.now(pytz.timezone('America/Mexico_City')).strftime('%Y-%m-%d %H:%M:%S')}", styles['BodyText']))
        elements.append(Spacer(1, 20))

        # Resumen general
        total_servicios = len(st.session_state.servicios)
        total_personal = 0

        for servicio, personal in st.session_state.servicios.items():
            total_personal += len(personal)

        # Tabla de resumen
        summary_data = [
            ["Total Servicios", str(total_servicios)],
            ["Total Personal", str(total_personal)],
            ["Personal por Servicio", f"{total_personal/total_servicios:.1f}" if total_servicios > 0 else "0"],
            ["Usuario", user_info['nombre']],
            ["Número Económico", user_info['numero_economico']],
            ["Turno Laboral", user_info.get('turno', 'N/A')]
        ]

        summary_table = Table(summary_data, colWidths=[2.5*inch, 2.5*inch])
        summary_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 10),
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 30))

        # Distribución por servicio
        elements.append(Paragraph("DISTRIBUCIÓN POR SERVICIO", styles['Heading2']))
        elements.append(Spacer(1, 15))

        # Crear tabla para cada servicio
        for servicio, personal in st.session_state.servicios.items():
            # Encabezado del servicio
            servicio_style = ParagraphStyle(
                'ServicioHeader',
                parent=styles['Heading3'],
                fontSize=12,
                spaceAfter=10,
                textColor=colors.darkblue
            )

            personal_count = len(personal)

            elements.append(Paragraph(f"{servicio} - {personal_count} profesional(es)", servicio_style))

            # Personal de este servicio
            if personal:
                personal_data = [["Nombre", "Rol", "No. Económico", "Hora Entrada"]]
                for persona in personal:
                    personal_data.append([
                        persona.get('nombre', 'N/A'),
                        persona.get('rol', 'N/A').replace('-', ' ').title(),
                        persona.get('numero_economico', 'N/A'),
                        persona.get('hora_entrada', 'N/A')
                    ])

                personal_table = Table(personal_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch, 1*inch])
                personal_table.setStyle(TableStyle([
                    ('FONT', (0, 0), (-1, -1), 'Helvetica', 8),
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 9),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))

                elements.append(personal_table)
            else:
                # Mostrar que el servicio está vacío
                elements.append(Paragraph("🔄 Sin enfermeras asignadas", styles['BodyText']))
                elements.append(Spacer(1, 10))

            elements.append(Spacer(1, 20))

            # Agregar salto de página cada 2 servicios para mejor legibilidad
            if list(st.session_state.servicios.keys()).index(servicio) % 2 == 1:
                elements.append(PageBreak())

        # Leyenda de roles
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("LEYENDA DE ROLES", styles['Heading3']))

        roles_data = [
            ["Rol", "Color", "Descripción"],
            ["Especialista", "#ff5252", "Enfermera especialista"],
            ["General A", "#4caf50", "Enfermera general turno A"],
            ["General B", "#2196f3", "Enfermera general turno B"],
            ["General C", "#9c27b0", "Enfermera general turno C"],
            ["Camillero", "#ff9800", "Personal de apoyo/camillero"]
        ]

        roles_table = Table(roles_data, colWidths=[1.5*inch, 1*inch, 2.5*inch])
        roles_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 8),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        elements.append(roles_table)
        elements.append(Spacer(1, 20))

        # Información del sistema
        elements.append(Paragraph("INFORMACIÓN DEL SISTEMA", styles['Heading3']))

        system_info = [
            ["Servidor SFTP", CONFIG.REMOTE['HOST']],
            ["Usuario SFTP", CONFIG.REMOTE['USER']],
            ["Directorio", CONFIG.REMOTE['DIR']],
            ["Modo Debug", "Activado" if CONFIG.DEBUG_MODE else "Desactivado"],
            ["Modo Supervisor", "Activado" if CONFIG.SUPERVISOR_MODE else "Desactivado"],
            ["Generado automáticamente", "Sistema de Supervisión de Turno"]
        ]

        system_table = Table(system_info, colWidths=[2*inch, 3*inch])
        system_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 8),
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 8),
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        elements.append(system_table)

        # Generar PDF
        doc.build(elements)

        # Obtener bytes del PDF
        pdf_bytes = buffer.getvalue()
        buffer.close()

        return pdf_bytes

    except Exception as e:
        st.error(f"Error generando PDF de distribución: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback completo: {traceback.format_exc()}")
        return None

def show_configuration_pdf_button(user_info):
    """Muestra el botón para generar PDF de distribución en el sidebar"""
    if user_info['puesto'].lower() in ['supervision turno', 'jefatura servicio']:
        st.sidebar.markdown("---")
        st.sidebar.markdown("### 🖨️ Herramientas de Supervisión")

        if st.sidebar.button("📋 Generar Reporte de Distribución PDF", use_container_width=True):
            with st.spinner("Generando reporte de distribución..."):
                pdf_bytes = generate_configuration_pdf(user_info)
                if pdf_bytes:
                    # Crear nombre de archivo con timestamp
                    timestamp = datetime.now(pytz.timezone('America/Mexico_City')).strftime("%Y%m%d_%H%M%S")
                    filename = f"distribucion_turno_{user_info['turno']}_{timestamp}.pdf"

                    # Botón de descarga
                    st.sidebar.download_button(
                        label="📥 Descargar Reporte de Distribución",
                        data=pdf_bytes,
                        file_name=filename,
                        mime="application/pdf",
                        use_container_width=True
                    )
                    st.sidebar.success("✅ PDF generado exitosamente")

                    # Registrar evento de seguridad
                    log_security_event("pdf_generated", user_info,
                                     f"Reporte de distribución generado: {filename}")
                else:
                    st.sidebar.error("❌ Error al generar el PDF")


def initialize_session_state(user_servicio, user_info):
    """Inicializa el estado de la sesión con medidas de seguridad y filtrando por turno laboral y fecha_turno"""
    operation_id = f"init_session_{uuid.uuid4()}"
    activity_monitor.start_operation(operation_id, user_info, "init_session")

    try:
        if 'servicios' not in st.session_state:
            # Cargar datos de enfermeras con medidas de seguridad
            enfermeras_df = load_csv_data(CONFIG.FILES["enfermeras"], user_info)

            if enfermeras_df is None:
                st.error("No se pudieron cargar los datos de enfermeras")
                activity_monitor.end_operation(operation_id, "failed")
                return

            # Limpiar y normalizar datos
            enfermeras_df.columns = enfermeras_df.columns.str.strip().str.lower()

            # DEBUG: Mostrar estructura del archivo para identificar la columna correcta
            if CONFIG.DEBUG_MODE:
                st.info("🔍 Estructura del archivo de enfermeras:")
                st.write("Columnas disponibles:", enfermeras_df.columns.tolist())
                st.write("Primeras filas:")
                st.write(enfermeras_df.head())

            # OBTENER TURNO LABORAL DEL USUARIO ACTUAL para filtrar
            turno_usuario = user_info.get('turno', '').strip()

            # OBTENER FECHA_TURNO DEL USUARIO ACTUAL
            fecha_turno_usuario = None
            if 'fecha_turno' in enfermeras_df.columns and user_info.get('numero_economico'):
                # Buscar la fecha_turno del usuario actual en el archivo
                usuario_id = str(user_info['numero_economico']).strip()
                enfermeras_df['numero_economico'] = enfermeras_df['numero_economico'].astype(str).str.strip()
                usuario_data = enfermeras_df[enfermeras_df['numero_economico'] == usuario_id]

                if not usuario_data.empty and 'fecha_turno' in usuario_data.columns:
                    fecha_turno_usuario = usuario_data.iloc[0]['fecha_turno']
                    if CONFIG.DEBUG_MODE:
                        st.info(f"🔍 Fecha_turno del usuario encontrada: {fecha_turno_usuario}")

            # Si no tenemos turno del usuario, intentar obtenerlo del archivo de claves
            if not turno_usuario:
                claves_df = load_csv_data(CONFIG.FILES["claves"], user_info)
                if claves_df is not None and 'turno_laboral' in claves_df.columns:
                    usuario_id = str(user_info['numero_economico']).strip()
                    claves_df['numero_economico'] = claves_df['numero_economico'].astype(str).str.strip()
                    usuario_clave = claves_df[claves_df['numero_economico'] == usuario_id]
                    if not usuario_clave.empty:
                        turno_usuario = usuario_clave.iloc[0]['turno_laboral']
                        user_info['turno'] = turno_usuario  # Actualizar user_info

            # Si aún no tenemos turno, usar vespertino por defecto
            if not turno_usuario:
                turno_usuario = "Vespertino (14:30-21:00)"
                user_info['turno'] = turno_usuario
                st.warning("⚠️ No se detectó turno del usuario, usando Vespertino por defecto")

            if CONFIG.DEBUG_MODE:
                st.info(f"🔍 Filtrando por turno: {turno_usuario}")
                st.info(f"🔍 Filtrando por fecha_turno: {fecha_turno_usuario}")
                st.info(f"📊 Total enfermeras antes de filtrar: {len(enfermeras_df)}")

            # FILTRAR SOLO ENFERMERAS DEL TURNO Y FECHA_TURNO (NO por servicio)
            enfermeras_filtradas = filtrar_enfermeras_por_turno_servicio(
                enfermeras_df,
                turno_usuario,
                None,  # ← No filtrar por servicio
                fecha_turno_usuario  # ← Nueva: filtrar por fecha_turno
            )

            if CONFIG.DEBUG_MODE:
                st.info(f"📊 Enfermeras después de filtrar por turno y fecha_turno: {len(enfermeras_filtradas)}")

            # Identificar la columna que contiene la hora de entrada
            posibles_nombres_hora = ['hora_entrada', 'hora entrada', 'entrada', 'hora', 'time', 'checkin']
            columna_hora_entrada = None

            for col in enfermeras_filtradas.columns:
                if any(nombre in col for nombre in posibles_nombres_hora):
                    columna_hora_entrada = col
                    break

            # Si no encontramos una columna específica, usar la sexta columna (índice 5)
            if columna_hora_entrada is None and len(enfermeras_filtradas.columns) >= 6:
                columna_hora_entrada = enfermeras_filtradas.columns[5]  # Sexta columna (0-based index)
                if CONFIG.DEBUG_MODE:
                    st.info(f"⚠️ Usando columna por posición: {columna_hora_entrada}")

            if columna_hora_entrada is None:
                st.error("No se pudo identificar la columna de hora de entrada")
                activity_monitor.end_operation(operation_id, "failed")
                return

            if CONFIG.DEBUG_MODE:
                st.info(f"📊 Columna de hora de entrada identificada: '{columna_hora_entrada}'")
                st.write("Valores únicos en esta columna:", enfermeras_filtradas[columna_hora_entrada].unique()[:10])

            # Definir puestos válidos (los mismos que en la función de filtro)
            puestos_validos = [
                'enfermera general a', 'enfermera general b', 'enfermera general c',
                'enfermera especialista', 'ayudante general', 'camillero'
            ]

            # Filtrar enfermeras válidas (con hora de entrada válida - no vacía, no solo espacios, y NO "NO")
            enfermeras_validas = enfermeras_filtradas[
                (~enfermeras_filtradas[columna_hora_entrada].isna()) &
                (enfermeras_filtradas[columna_hora_entrada].astype(str).apply(lambda x: not x.strip() == '')) &  # No vacío después de quitar espacios
                (enfermeras_filtradas[columna_hora_entrada].astype(str).apply(lambda x: x.strip().upper() != 'NO')) &  # Excluir "NO"
                (enfermeras_filtradas['puesto'].str.strip().str.lower().isin(puestos_validos))
            ]

            if CONFIG.DEBUG_MODE:
                st.info(f"📊 Enfermeras totales: {len(enfermeras_filtradas)}, Válidas: {len(enfermeras_validas)}")
                st.write("Enfermeras filtradas (primeras 5):")
                st.write(enfermeras_validas.head())

            # OBTENER LA LISTA COMPLETA DE SERVICIOS (SIEMPRE MOSTRAR TODOS)
            servicios_completos = obtener_servicios()

            # Crear estructura de servicios con datos reales - INCLUYENDO SERVICIOS VACÍOS
            servicios = {}

            # Inicializar todos los servicios, incluso los vacíos
            for servicio_nombre in servicios_completos:
                servicios[servicio_nombre] = []

            # Agregar enfermeras a sus servicios correspondientes
            for _, enfermera in enfermeras_validas.iterrows():
                servicio = str(enfermera['servicio']).strip() if not pd.isna(enfermera['servicio']) else ""

                # Solo agregar si el servicio está en la lista completa
                if servicio and servicio in servicios:
                    puesto = enfermera['puesto'].strip().lower() if not pd.isna(enfermera['puesto']) else ""

                    # Asignar color según el rol
                    if 'general a' in puesto:
                        color = "#4caf50"
                        rol = "general-a"
                    elif 'general b' in puesto:
                        color = "#2196f3"
                        rol = "general-b"
                    elif 'general c' in puesto:
                        color = "#9c27b0"
                        rol = "general-c"
                    elif 'camillero' in puesto:
                        color = "#ff9800"
                        rol = "camillero"
                    elif 'ayudante' in puesto:
                        color = "#ff9800"  # Mismo color que camillero
                        rol = "ayudante"
                    else:
                        color = "#9c27b0"
                        rol = "general-a"

                    # Sanitizar datos
                    nombre = sanitize_input(enfermera.get('nombre_completo', ''))
                    numero_economico = sanitize_input(str(enfermera.get('numero_economico', '')))
                    hora_entrada_val = sanitize_input(str(enfermera.get(columna_hora_entrada, '')))

                    servicios[servicio].append({
                        "nombre": nombre,
                        "rol": rol,
                        "color": color,
                        "numero_economico": numero_economico,
                        "hora_entrada": hora_entrada_val
                    })

            # DEBUG: Mostrar distribución final de servicios
            if CONFIG.DEBUG_MODE:
                st.info("📋 Distribución inicial de servicios (incluyendo vacíos):")
                for servicio_nombre, personal in servicios.items():
                    st.write(f"{servicio_nombre}: {len(personal)} enfermeras")
                    for p in personal:
                        st.write(f"  - {p['nombre']} ({p['numero_economico']}) - {p['rol']}")

            st.session_state.servicios = servicios

        if 'seleccion' not in st.session_state:
            st.session_state.seleccion = {"nombre": None, "servicio": None}

        if 'log_movimientos' not in st.session_state:
            st.session_state.log_movimientos = []

        # Almacenar información del usuario en session_state
        if 'user_info' not in st.session_state:
            st.session_state.user_info = user_info

        if 'user_servicio' not in st.session_state:
            st.session_state.user_servicio = user_servicio

        # Inicializar habitaciones si no existen
        if 'habitaciones' not in st.session_state:
            # Cargar datos de pacientes y enfermeras para crear estructura completa
            pacientes_df = load_csv_data(CONFIG.FILES["pacientes"], user_info)
            enfermeras_df = load_csv_data(CONFIG.FILES["enfermeras"], user_info)

            if pacientes_df is not None and enfermeras_df is not None:
                st.session_state.habitaciones = crear_estructura_habitaciones(
                    user_servicio, pacientes_df, enfermeras_df, user_info, fecha_turno_usuario
                )
            else:
                st.session_state.habitaciones = {}

        activity_monitor.end_operation(operation_id, "completed")

    except Exception as e:
        st.error(f"Error inicializando sesión: {str(e)}")
        log_security_event("session_init_error", user_info, f"Error inicializando sesión: {str(e)}")
        activity_monitor.end_operation(operation_id, "failed")


def main():
    """Función principal con medidas de seguridad integradas"""
    setup_page_config()
    load_custom_styles()

    try:
        # Autenticar usuario con medidas de seguridad
        authenticated, user_info = authenticate_user()
        if not authenticated:
            return

        # Verificar que todos los archivos existan (con manejo de nombres alternativos)
        verificar_archivos_servidor(user_info)

        # Inicializar estado de la sesión con el servicio del usuario
        initialize_session_state(user_info['servicio'], user_info)
        show_logo()

        # ==================== SIDEBAR COMPLETO ====================
        # Información del usuario
        st.sidebar.success(f"Usuario: {user_info['nombre']}")
        st.sidebar.info(f"Puesto: {user_info['puesto']}")
        st.sidebar.info(f"Turno: {user_info['turno']}")
        if user_info.get('servicio'):
            st.sidebar.info(f"Servicio: {user_info['servicio']}")

        # === HERRAMIENTAS DE SUPERVISIÓN ===
        show_configuration_pdf_button(user_info)

        # === INICIO DE JORNADA ===
        manejar_inicio_jornada(user_info)

        # === VISUALIZACIÓN DE LOGS ===
        st.sidebar.markdown("---")
        st.sidebar.markdown("### 📊 Visualización de Logs")

        # Obtener lista de logs disponibles (con recarga forzada)
        logs_disponibles = listar_logs_disponibles(user_info)

        if logs_disponibles:
            log_seleccionado = st.sidebar.selectbox(
                "Seleccionar archivo de log:",
                logs_disponibles,
                key="log_selector"
            )

            if st.sidebar.button("👁️ Ver contenido del log", use_container_width=True, key="btn_ver_log"):
                with st.spinner("Cargando contenido del log..."):
                    contenido = obtener_contenido_log(log_seleccionado, user_info)
                    if contenido:
                        # Almacenar en session_state para mostrarlo en el área principal
                        st.session_state.log_contenido = contenido
                        st.session_state.log_nombre = log_seleccionado
                        st.sidebar.success("✅ Log cargado correctamente")
                        st.rerun()  # Forzar rerun para mostrar inmediatamente
                    else:
                        st.sidebar.error("❌ No se pudo cargar el contenido del log")
        else:
            st.sidebar.info("📝 No hay logs disponibles para visualizar")

        # Botón para recargar lista de logs
        if st.sidebar.button("🔄 Recargar lista de logs", use_container_width=True, key="btn_recargar_logs"):
            with st.spinner("Recargando lista de logs..."):
                # Limpiar cache de logs
                if 'log_contenido' in st.session_state:
                    del st.session_state.log_contenido
                if 'log_nombre' in st.session_state:
                    del st.session_state.log_nombre
                st.rerun()

        # === RECONSTRUIR DESDE LOG ===
        st.sidebar.markdown("---")
        st.sidebar.markdown("### 🔄 Reconstruir Distribución")

        if logs_disponibles:
            log_seleccionado_reconstruir = st.sidebar.selectbox(
                "Seleccionar log para reconstruir:",
                logs_disponibles,
                key="log_reconstruir_selector"
            )

            if st.sidebar.button("🔄 Reconstruir desde este log", use_container_width=True, key="btn_reconstruir_log"):
                with st.spinner("Reconstruyendo desde el log histórico..."):
                    # Guardar información actual antes de reconstruir
                    log_movimientos_backup = st.session_state.get('log_movimientos', [])

                    # Reconstruir desde el log seleccionado
                    servicios_reconstruidos = reconstruir_desde_log(user_info['servicio'], log_seleccionado_reconstruir, user_info)

                    if servicios_reconstruidos is not None:
                        st.session_state.servicios = servicios_reconstruidos
                        # Mantener los movimientos actuales para poder agregar más
                        st.session_state.log_movimientos = log_movimientos_backup
                        st.sidebar.success("✅ Estado reconstruido desde el log histórico")
                        st.success("Distribución reconstruida desde el log seleccionado")
                        st.rerun()
                    else:
                        st.sidebar.error("❌ Error al reconstruir desde el log")
        else:
            st.sidebar.info("📝 No hay logs históricos disponibles")

        # === GESTIÓN DE SESIÓN ===
        st.sidebar.markdown("---")
        st.sidebar.markdown("### ⚙️ Gestión de Sesión")

        # Opción para restaurar configuración original
        if st.sidebar.button("📋 Cargar distribución original", use_container_width=True, key="btn_cargar_original"):
            with st.spinner("Cargando distribución original..."):
                # Limpiar solo los datos de distribución, mantener autenticación
                keys_to_clear = ['servicios', 'seleccion', 'log_movimientos', 'habitaciones', 'log_contenido', 'log_nombre']
                for key in keys_to_clear:
                    if key in st.session_state:
                        del st.session_state[key]

                # Recargar distribución original
                initialize_session_state(user_info['servicio'], user_info)

                st.sidebar.success("✅ Distribución original cargada")
                st.success("Distribución original restaurada desde archivos remotos")
                log_security_event("session_reset", user_info, "Distribución original cargada")
                st.rerun()

        # Opción para descartar cambios y salir
        if st.sidebar.button("🚪 Salir y descartar cambios", use_container_width=True, key="btn_salir"):
            with st.spinner("Limpiando sesión..."):
                log_security_event("session_cleanup", user_info, "Sesión limpiada por usuario")
                st.session_state.clear()
                st.sidebar.success("✅ Sesión limpiada exitosamente")
                st.rerun()

        # Mostrar estado del sistema de seguridad
        if CONFIG.DEBUG_MODE:
            st.sidebar.markdown("---")
            st.sidebar.markdown("### 🔐 Estado de Seguridad")
            with st.sidebar.expander("Ver detalles de seguridad"):
                st.write(f"Circuit Breaker: {circuit_breaker.failure_count}/{circuit_breaker.threshold}")
                st.write(f"Rate Limits: {len(rate_limiter.requests)} usuarios monitoreados")
                st.write(f"Operaciones activas: {len(activity_monitor.get_active_operations())}")

        # ==================== CONTENIDO PRINCIPAL ====================
        show_main_content()

        # Mostrar contenido del log si se ha seleccionado uno
        if hasattr(st.session_state, 'log_contenido') and st.session_state.log_contenido:
            st.markdown("---")
            mostrar_contenido_log_tabular(st.session_state.log_contenido, st.session_state.log_nombre)

        show_summary(user_info)

    except Exception as e:
        st.error(f"❌ Error crítico en la aplicación: {str(e)}")
        log_security_event("critical_error", user_info if 'user_info' in st.session_state else {},
                         f"Error crítico: {str(e)}")
        if CONFIG.DEBUG_MODE:
            import traceback
            st.error(f"Traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    main()
