from io import StringIO, BytesIO
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.units import inch
import streamlit as st
import pandas as pd
import os
from datetime import datetime, timedelta, time
import tempfile
import paramiko
from io import StringIO
import pytz
import numpy as np
import time
import hashlib
import re
import uuid
import base64
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

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
            'TIMEOUT_SECONDS': 30
        }
        
        # File Configuration - Usando secrets.toml
        self.FILES = {
            "claves": st.secrets["file_creacion_enfermeras2"],
            "asistencia": st.secrets["file_enfermeras2"]
        }
        
        # App Configuration
        self.DEBUG_MODE = st.secrets.get("debug_mode", False)
        
        # Turnos disponibles
        self.TURNOS = [
            "Matutino (7:00-15:00)",
            "Vespertino (14:30-21:00)",
            "Nocturno (A y B) (20:30-8:00)",
            "Jornada Acumulada (8:00-20:00)"
        ]
        
        # Puestos disponibles
        self.PUESTOS = [
            "jefatura departamento",
            "supervision turno", 
            "jefatura servicio",
            "enfermera general A",
            "enfermera general B",
            "enfermera general C",
            "enfermera especialista",
            "ayudante general",
            "camillero"
        ]
        
        # Servicios disponibles
        self.SERVICIOS = [
            "UNIDAD CORONARIA",
            "CARDIOLOGÍA ADULTOS III",
            "CARDIONEUMOLOGÍA",
            "NEFROLOGÍA",
            "HEMODINÁMICA",
            "TERAPIA INTENSIVA CARDIOVASCULAR",
            "QUIRÓFANO",
            "CARDIOLOGÍA PEDIÁTRICA",
            "CARDIOLOGÍA ADULTOS VII",
            "HOSPITALIZACIÓN OCTAVO PISO",
            "HOSPITALIZACIÓN NOVENO PISO",
            "CENTRAL DE EQUIPO Y ESTERILIZACIÓN",
            "COMITÉ DE CONTROL DE INFECCIONES ASOCIADAS A LA ATENCIÓN DE LA SALUD",
            "VENTILOTERAPIA",
            "CONSULTA EXTERNA",
            "BANCO DE SANGRE",
            "CLÍNICAS DE DIAGNÓSTICO Y TRATAMIENTO",
            "CLÍNICA DE CUIDADOS PALIATIVOS/APOYO VITAL",
            "DIRECCIÓN DE ENFERMERÍA Y DEPARTAMENTOS"
        ]
        
        # Opciones de suplencia
        self.SUPLENCIA_OPCIONES = ["SI", "NO"]
        
        # Opciones de incidencias
        self.INCIDENCIAS = {
            "DS": "Descanso",
            "VA": "Vacaciones",
            "VR": "Vacaciones de riesgo",
            "VP": "Vacaciones de premio",
            "ON": "Onomástico",
            "DE": "Económico",
            "AC": "Académico",
            "BE": "Beca",
            "FE": "Festivo",
            "CO": "Comisión Oficial",
            "FA": "Falta",
            "SU": "Suplencia",
            "SL": "Suspensión laboral",
            "IN": "Incapacidad",
            "IG": "Incapacidad por gravidez",
            "CM": "Cuidados Maternos",
            "LC": "Licencia con goce de sueldo",
            "LS": "Licencia sin goce de sueldo",
            "LI": "Licencia sindical",
            "NC": "Comisión Sindical"
        }
        
        # Horas disponibles para hora_entrada
        self.HORAS_ENTRADA = [
            "NO",
            "6:00", "6:05", "6:10", "6:15", "6:20", "6:25", "6:30", "6:35", "6:40", "6:45", "6:50", "6:55",
            "7:00", "7:05", "7:10", "7:15", "7:20", "7:25", "7:30", "7:35", "7:40", "7:45", "7:50", "7:55",
            "8:00", "8:05", "8:10", "8:15", "8:20", "8:25", "8:30", "8:35", "8:40", "8:45", "8:50", "8:55",
            "9:00", "9:05", "9:10", "9:15", "9:20", "9:25", "9:30", "9:35", "9:40", "9:45", "9:50", "9:55",
            "10:00", "10:05", "10:10", "10:15", "10:20", "10:25", "10:30", "10:35", "10:40", "10:45", "10:50", "10:55",
            "11:00", "11:05", "11:10", "11:15", "11:20", "11:25", "11:30", "11:35", "11:40", "11:45", "11:50", "11:55",
            "12:00", "12:05", "12:10", "12:15", "12:20", "12:25", "12:30", "12:35", "12:40", "12:45", "12:50", "12:55",
            "13:00", "13:05", "13:10", "13:15", "13:20", "13:25", "13:30", "13:35", "13:40", "13:45", "13:50", "13:55",
            "14:00", "14:05", "14:10", "14:15", "14:20", "14:25", "14:30", "14:35", "14:40", "14:45", "14:50", "14:55",
            "15:00", "15:05", "15:10", "15:15", "15:20", "15:25", "15:30", "15:35", "15:40", "15:45", "15:50", "15:55",
            "16:00", "16:05", "16:10", "16:15", "16:20", "16:25", "16:30", "16:35", "16:40", "16:45", "16:50", "16:55",
            "17:00", "17:05", "17:10", "17:15", "17:20", "17:25", "17:30", "17:35", "17:40", "17:45", "17:50", "17:55",
            "18:00", "18:05", "18:10", "18:15", "18:20", "18:25", "18:30", "18:35", "18:40", "18:45", "18:50", "18:55",
            "19:00", "19:05", "19:10", "19:15", "19:20", "19:25", "19:30", "19:35", "19:40", "19:45", "19:50", "19:55",
            "20:00", "20:05", "20:10", "20:15", "20:20", "20:25", "20:30", "20:35", "20:40", "20:45", "20:50", "20:55",
            "21:00", "21:05", "21:10", "21:15", "21:20", "21:25", "21:30", "21:35", "21:40", "21:45", "21:50", "21:55"
        ]

CONFIG = Config()

# ====================
# FUNCIONES DE SEGURIDAD Y AUTENTICACIÓN
# ====================
def sanitize_input(input_data, max_length=100):
    """Sanitiza entradas para prevenir inyección"""
    if not isinstance(input_data, str):
        return ""
    
    # Remover caracteres peligrosos
    sanitized = re.sub(r'[;|&$`<>{}]', '', input_data)
    # Limitar longitud
    return sanitized[:max_length].strip()

def constant_time_compare(val1, val2):
    """Comparación en tiempo constante para prevenir timing attacks"""
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0

def authenticate_user():
    """Autentica al usuario con credenciales fijas"""
    st.title("🔐 Sistema de Administración - Archivo de Claves")

    if 'auth_stage' not in st.session_state:
        st.session_state.auth_stage = 'username'
        st.session_state.auth_attempts = 0
        st.session_state.last_auth_attempt = 0

    # Prevenir brute force
    current_time = time.time()
    if (st.session_state.auth_attempts >= 3 and
        current_time - st.session_state.last_auth_attempt < 300):
        st.error("🔒 Demasiados intentos fallidos. Espere 5 minutos antes de intentar nuevamente.")
        return False, None

    if st.session_state.auth_stage == 'username':
        with st.form("auth_form_username"):
            username = st.text_input("Usuario", max_chars=20)
            username = sanitize_input(username)

            submitted = st.form_submit_button("Continuar")

            if submitted:
                st.session_state.last_auth_attempt = current_time
                st.session_state.auth_attempts += 1

                if not username:
                    st.error("Por favor ingrese su usuario")
                    return False, None

                # Verificar usuario
                if username != "administracion":
                    st.error("❌ Usuario incorrecto")
                    return False, None

                st.session_state.username = username
                st.session_state.auth_stage = 'password'
                st.rerun()

    elif st.session_state.auth_stage == 'password':
        with st.form("auth_form_password"):
            st.info(f"👤 Usuario: administracion")
            
            password = st.text_input("Contraseña", type="password")
            confirm = st.form_submit_button("Iniciar Sesión")

            if confirm:
                st.session_state.last_auth_attempt = current_time
                st.session_state.auth_attempts += 1

                if not password:
                    st.error("❌ Por favor ingrese su contraseña")
                    return False, None

                # Verificar contraseña
                if password != "gabylira2026":
                    st.error("❌ Contraseña incorrecta")
                    return False, None

                # Autenticación exitosa
                st.session_state.auth_attempts = 0
                st.success("✅ Autenticación exitosa")
                st.session_state.auth_stage = 'authenticated'
                
                # Crear datos de usuario simulados
                st.session_state.user_data = {
                    'numero_economico': 'admin001',
                    'puesto': 'administración',
                    'nombre_completo': 'Usuario Administrador',
                    'turno_laboral': 'Administrativo'
                }
                
                st.rerun()

    elif st.session_state.auth_stage == 'authenticated':
        return True, st.session_state.user_data

    return False, None

# ====================
# FUNCIONES SSH/SFTP
# ====================
class SSHManager:
    @staticmethod
    def get_connection():
        """Establece conexión SSH segura"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                hostname=CONFIG.REMOTE['HOST'],
                port=CONFIG.REMOTE['PORT'],
                username=CONFIG.REMOTE['USER'],
                password=CONFIG.REMOTE['PASSWORD'],
                timeout=CONFIG.REMOTE['TIMEOUT_SECONDS'],
                banner_timeout=30
            )
            return ssh
        except Exception as e:
            st.error(f"Error de conexión SSH: {str(e)}")
            return None

    @staticmethod
    def get_remote_file(remote_filename):
        """Lee archivo remoto con manejo de errores"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return None

        try:
            sftp = ssh.open_sftp()
            remote_path = os.path.join(CONFIG.REMOTE['DIR'], remote_filename)

            with sftp.file(remote_path, 'r') as f:
                content = f.read().decode('utf-8')

            return content
        except FileNotFoundError:
            # Si el archivo no existe, devolver contenido vacío
            return ""
        except Exception as e:
            st.error(f"Error leyendo archivo remoto: {str(e)}")
            return None
        finally:
            ssh.close()

    @staticmethod
    def put_remote_file(remote_path, content):
        """Escribe archivo remoto con manejo de errores"""
        ssh = SSHManager.get_connection()
        if not ssh:
            return False

        try:
            sftp = ssh.open_sftp()

            # Crear archivo temporal
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp', encoding='utf-8') as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            try:
                sftp.put(temp_file_path, remote_path)
                return True
            except Exception as e:
                st.error(f"Error subiendo archivo al servidor: {str(e)}")
                return False
            finally:
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
        except Exception as e:
            st.error(f"Error en operación SFTP: {str(e)}")
            return False
        finally:
            try:
                ssh.close()
            except:
                pass

# ====================
# FUNCIONES DE ARCHIVOS
# ====================
def cargar_archivo_claves():
    """Carga el archivo de claves con estructura completa"""
    content = SSHManager.get_remote_file(CONFIG.FILES["claves"])
    if content is None:
        return None

    # Definir estructura completa esperada
    columnas_completas = [
        'numero_economico', 'puesto', 'nombre_completo', 'servicio', 
        'turno_laboral', 'password', 'correo_electronico', 'suplencia'
    ]

    if content.strip() == "":
        # Devolver DataFrame vacío con todas las columnas esperadas
        return pd.DataFrame(columns=columnas_completas)

    try:
        df = pd.read_csv(StringIO(content))

        # Asegurar que todas las columnas existan
        for col in columnas_completas:
            if col not in df.columns:
                if col == 'suplencia':
                    df[col] = "NO"  # Valor por defecto para suplencia
                else:
                    df[col] = ""  # Valores por defecto para campos de texto

        # Limpiar y normalizar datos con verificación de existencia
        if 'numero_economico' in df.columns:
            df['numero_economico'] = df['numero_economico'].astype(str).str.strip()
        else:
            df['numero_economico'] = ""

        if 'nombre_completo' in df.columns:
            df['nombre_completo'] = df['nombre_completo'].astype(str).str.strip()
        else:
            df['nombre_completo'] = ""

        if 'puesto' in df.columns:
            df['puesto'] = df['puesto'].astype(str).str.strip().str.lower()
        else:
            df['puesto'] = ""

        if 'servicio' in df.columns:
            df['servicio'] = df['servicio'].astype(str).str.strip()
        else:
            df['servicio'] = ""

        if 'password' in df.columns:
            df['password'] = df['password'].astype(str).str.strip()
        else:
            df['password'] = ""

        if 'turno_laboral' in df.columns:
            df['turno_laboral'] = df['turno_laboral'].astype(str).str.strip()
        else:
            df['turno_laboral'] = ""

        if 'correo_electronico' in df.columns:
            df['correo_electronico'] = df['correo_electronico'].astype(str).str.strip()
        else:
            df['correo_electronico'] = ""

        if 'suplencia' in df.columns:
            df['suplencia'] = df['suplencia'].astype(str).str.strip().str.upper()
            # Asegurar que los valores de suplencia sean válidos
            df['suplencia'] = df['suplencia'].apply(lambda x: x if x in ['SI', 'NO'] else 'NO')
        else:
            df['suplencia'] = "NO"

        return df

    except Exception as e:
        st.error(f"Error procesando archivo {CONFIG.FILES['claves']}: {str(e)}")
        # En caso de error, devolver DataFrame vacío con estructura correcta
        return pd.DataFrame(columns=columnas_completas)

def cargar_archivo_asistencia():
    """Carga el archivo de asistencia con estructura completa"""
    content = SSHManager.get_remote_file(CONFIG.FILES["asistencia"])
    if content is None:
        return None

    # Definir estructura completa esperada
    columnas_completas = [
        'fecha', 'fecha_turno', 'numero_economico', 'puesto', 'nombre_completo', 
        'servicio', 'turno_laboral', 'hora_entrada', 'incidencias', 'suplencia'
    ]

    if content.strip() == "":
        # Devolver DataFrame vacío con todas las columnas esperadas
        return pd.DataFrame(columns=columnas_completas)

    try:
        df = pd.read_csv(StringIO(content))

        # Asegurar que todas las columnas existan
        for col in columnas_completas:
            if col not in df.columns:
                df[col] = ""  # Valores por defecto para campos de texto

        # Limpiar y normalizar datos con verificación de existencia
        if 'numero_economico' in df.columns:
            df['numero_economico'] = df['numero_economico'].astype(str).str.strip()
        else:
            df['numero_economico'] = ""

        if 'nombre_completo' in df.columns:
            df['nombre_completo'] = df['nombre_completo'].astype(str).str.strip()
        else:
            df['nombre_completo'] = ""

        if 'puesto' in df.columns:
            df['puesto'] = df['puesto'].astype(str).str.strip().str.lower()
        else:
            df['puesto'] = ""

        if 'servicio' in df.columns:
            df['servicio'] = df['servicio'].astype(str).str.strip()
        else:
            df['servicio'] = ""

        if 'turno_laboral' in df.columns:
            df['turno_laboral'] = df['turno_laboral'].astype(str).str.strip()
        else:
            df['turno_laboral'] = ""

        if 'hora_entrada' in df.columns:
            df['hora_entrada'] = df['hora_entrada'].astype(str).str.strip()
            # Reemplazar 'nan' por cadena vacía
            df['hora_entrada'] = df['hora_entrada'].replace('nan', '')
        else:
            df['hora_entrada'] = ""

        if 'incidencias' in df.columns:
            df['incidencias'] = df['incidencias'].astype(str).str.strip()
            # Reemplazar 'nan' por cadena vacía
            df['incidencias'] = df['incidencias'].replace('nan', '')
        else:
            df['incidencias'] = ""

        if 'suplencia' in df.columns:
            df['suplencia'] = df['suplencia'].astype(str).str.strip().str.upper()
            # Asegurar que los valores de suplencia sean válidos
            df['suplencia'] = df['suplencia'].apply(lambda x: x if x in ['SI', 'NO'] else 'NO')
        else:
            df['suplencia'] = "NO"

        if 'fecha' in df.columns:
            df['fecha'] = df['fecha'].astype(str).str.strip()
        else:
            df['fecha'] = ""

        if 'fecha_turno' in df.columns:
            df['fecha_turno'] = df['fecha_turno'].astype(str).str.strip()
        else:
            df['fecha_turno'] = ""

        return df

    except Exception as e:
        st.error(f"Error procesando archivo {CONFIG.FILES['asistencia']}: {str(e)}")
        # En caso de error, devolver DataFrame vacío con estructura correcta
        return pd.DataFrame(columns=columnas_completas)

def guardar_archivo_claves(df):
    """Guarda el archivo de claves de enfermeras"""
    remote_path = os.path.join(CONFIG.REMOTE['DIR'], CONFIG.FILES["claves"])
    csv_content = df.to_csv(index=False)

    if SSHManager.put_remote_file(remote_path, csv_content):
        if CONFIG.DEBUG_MODE:
            st.info("✅ Archivo de claves guardado correctamente")
        return True
    else:
        st.error("❌ Error al guardar el archivo de claves")
        return False

def guardar_archivo_asistencia(df):
    """Guarda el archivo de asistencia"""
    remote_path = os.path.join(CONFIG.REMOTE['DIR'], CONFIG.FILES["asistencia"])
    csv_content = df.to_csv(index=False)

    if SSHManager.put_remote_file(remote_path, csv_content):
        if CONFIG.DEBUG_MODE:
            st.info("✅ Archivo de asistencia guardado correctamente")
        return True
    else:
        st.error("❌ Error al guardar el archivo de asistencia")
        return False

def crear_registro_asistencia_manual(numero_economico, hora_entrada, incidencias, fecha_personalizada=None, hora_personalizada=None):
    """Crea un registro manual en el archivo de asistencia con los datos específicos"""
    try:
        # Cargar archivo de asistencia
        df_asistencia = cargar_archivo_asistencia()
        if df_asistencia is None:
            return False

        # Determinar fechas según si se proporciona fecha personalizada
        if fecha_personalizada and hora_personalizada:
            # Combinar fecha y hora personalizadas
            fecha_completa = f"{fecha_personalizada} {hora_personalizada}"
            fecha_turno = fecha_personalizada
        else:
            # Usar fecha actual (comportamiento original)
            fecha_completa = datetime.now().strftime("%Y-%m-%d %H:%M")
            fecha_turno = datetime.now().strftime("%Y-%m-%d")

        # Cargar datos del usuario desde claves para obtener información completa
        df_claves = cargar_archivo_claves()
        if df_claves is None:
            return False

        usuario_clave = df_claves[df_claves['numero_economico'] == numero_economico]
        if usuario_clave.empty:
            return False

        usuario = usuario_clave.iloc[0]

        # Eliminar cualquier registro existente para este usuario en la fecha del turno (evitar duplicados)
        df_asistencia = df_asistencia[
            ~((df_asistencia['numero_economico'] == numero_economico) & 
              (df_asistencia['fecha_turno'] == fecha_turno))
        ]

        # Crear nuevo registro de asistencia
        nuevo_registro_asistencia = {
            'fecha': fecha_completa,
            'fecha_turno': fecha_turno,
            'numero_economico': numero_economico,
            'puesto': usuario['puesto'],
            'nombre_completo': usuario['nombre_completo'],
            'servicio': usuario['servicio'],
            'turno_laboral': usuario['turno_laboral'],
            'hora_entrada': hora_entrada,
            'incidencias': incidencias,
            'suplencia': usuario['suplencia']
        }

        # Agregar nuevo registro
        df_asistencia = pd.concat([df_asistencia, pd.DataFrame([nuevo_registro_asistencia])], ignore_index=True)

        # Guardar archivo de asistencia
        return guardar_archivo_asistencia(df_asistencia)

    except Exception as e:
        st.error(f"Error creando registro de asistencia: {str(e)}")
        return False

def actualizar_registro_asistencia_manual(numero_original, nuevo_numero, hora_entrada, incidencias, fecha_personalizada=None, hora_personalizada=None):
    """Actualiza el registro en asistencia con los nuevos datos"""
    try:
        # Cargar archivo de asistencia
        df_asistencia = cargar_archivo_asistencia()
        if df_asistencia is None:
            return False

        # Determinar fechas según si se proporciona fecha personalizada
        if fecha_personalizada and hora_personalizada:
            # Combinar fecha y hora personalizadas
            fecha_completa = f"{fecha_personalizada} {hora_personalizada}"
            fecha_turno = fecha_personalizada
        else:
            # Usar fecha actual (comportamiento original)
            fecha_completa = datetime.now().strftime("%Y-%m-%d %H:%M")
            fecha_turno = datetime.now().strftime("%Y-%m-%d")

        # Cargar datos del usuario actualizado desde claves
        df_claves = cargar_archivo_claves()
        if df_claves is None:
            return False

        usuario_clave = df_claves[df_claves['numero_economico'] == nuevo_numero]
        if usuario_clave.empty:
            return False

        usuario = usuario_clave.iloc[0]

        # Buscar y eliminar registros existentes para evitar duplicados
        mask_original = (df_asistencia['numero_economico'] == numero_original) & (df_asistencia['fecha_turno'] == fecha_turno)
        mask_nuevo = (df_asistencia['numero_economico'] == nuevo_numero) & (df_asistencia['fecha_turno'] == fecha_turno)
        
        # Eliminar registros existentes
        df_asistencia = df_asistencia[~(mask_original | mask_nuevo)]

        # Crear nuevo registro
        nuevo_registro = {
            'fecha': fecha_completa,
            'fecha_turno': fecha_turno,
            'numero_economico': nuevo_numero,
            'puesto': usuario['puesto'],
            'nombre_completo': usuario['nombre_completo'],
            'servicio': usuario['servicio'],
            'turno_laboral': usuario['turno_laboral'],
            'hora_entrada': hora_entrada,
            'incidencias': incidencias,
            'suplencia': usuario['suplencia']
        }
        
        df_asistencia = pd.concat([df_asistencia, pd.DataFrame([nuevo_registro])], ignore_index=True)

        # Guardar archivo de asistencia
        return guardar_archivo_asistencia(df_asistencia)

    except Exception as e:
        st.error(f"Error actualizando registro de asistencia: {str(e)}")
        return False

def sincronizar_baja_asistencia(numero_economico_eliminado, fecha_turno=None):
    """Sincroniza la baja de un usuario con el archivo de asistencia"""
    try:
        # Cargar archivo de asistencia existente
        df_asistencia = cargar_archivo_asistencia()
        
        if df_asistencia is None:
            return False
            
        # Determinar fecha del turno
        if not fecha_turno:
            fecha_turno = datetime.now().strftime("%Y-%m-%d")
        
        # Eliminar registros del usuario en asistencia para la fecha del turno
        df_asistencia_actualizado = df_asistencia[
            ~((df_asistencia['numero_economico'] == numero_economico_eliminado) & 
              (df_asistencia['fecha_turno'] == fecha_turno))
        ]
        
        # Guardar archivo de asistencia actualizado
        return guardar_archivo_asistencia(df_asistencia_actualizado)
        
    except Exception as e:
        st.error(f"Error en sincronización de baja con asistencia: {str(e)}")
        return False

# ====================
# FUNCIONES DE INTERFAZ
# ====================
def mostrar_creacion_claves(user_info):
    """Muestra la interfaz para creación de registros en archivo de claves"""
    st.header("📝 Creación de Usuarios en Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    with st.form("form_creacion_claves", clear_on_submit=True):
        col1, col2 = st.columns(2)

        with col1:
            numero_economico = st.text_input("Número Económico*", max_chars=10, key="num_economico_claves")
            puesto = st.selectbox(
                "Puesto*",
                options=CONFIG.PUESTOS,
                key="puesto_select_claves"
            )
            servicio = st.selectbox(
                "Servicio*",
                options=CONFIG.SERVICIOS,
                key="servicio_select_claves"
            )
            turno_laboral = st.selectbox("🕒 Turno laboral*", CONFIG.TURNOS, key="turno_select_claves")

        with col2:
            nombre_completo = st.text_input("Nombre Completo*", key="nombre_completo_claves")
            correo_electronico = st.text_input("Correo Electrónico", key="correo_claves")
            suplencia = st.selectbox("Suplencia*", options=CONFIG.SUPLENCIA_OPCIONES, key="suplencia_select_claves")
            password = st.text_input("Contraseña*", type="password", key="password_claves")
            password_confirm = st.text_input("Confirmar Contraseña*", type="password", key="password_confirm_claves")

        # Campos adicionales para asistencia
        st.markdown("---")
        st.subheader("📋 Datos de Asistencia")
        
        col3, col4 = st.columns(2)
        
        with col3:
            # Selector de fecha y hora personalizada
            st.subheader("🗓️ Fecha y Hora del Registro")
            fecha_personalizada = st.date_input(
                "Fecha*",
                value=datetime.now().date(),
                key="fecha_personalizada_creacion"
            )
            
            hora_personalizada = st.time_input(
                "Hora*",
                value=datetime.now().time(),
                key="hora_personalizada_creacion"
            )
            
            # Convertir a string en el formato requerido
            fecha_str = fecha_personalizada.strftime("%Y-%m-%d")
            hora_str = hora_personalizada.strftime("%H:%M")
            fecha_completa_str = f"{fecha_str} {hora_str}"
            
            st.info(f"**Fecha completa:** {fecha_completa_str}")
            st.info(f"**Fecha del turno:** {fecha_str}")
            
        with col4:
            hora_entrada = st.selectbox(
                "Hora de Entrada*",
                options=CONFIG.HORAS_ENTRADA,
                index=0,  # Por defecto "NO"
                key="hora_entrada_claves"
            )
            
            # Crear opciones para incidencias
            opciones_incidencias = ["NO"] + [f"{codigo} - {descripcion}" for codigo, descripcion in CONFIG.INCIDENCIAS.items()]
            incidencia_seleccionada = st.selectbox(
                "Incidencias*",
                options=opciones_incidencias,
                key="incidencia_select_claves"
            )
            
            # Extraer solo el código de la incidencia si se seleccionó algo diferente a "NO"
            incidencia_codigo = "NO"
            if incidencia_seleccionada != "NO":
                incidencia_codigo = incidencia_seleccionada.split(" - ")[0]

        submitted = st.form_submit_button("✅ Crear Usuario y Registro de Asistencia")

        if submitted:
            # Validaciones
            if not all([numero_economico, nombre_completo, puesto, servicio, turno_laboral, password]):
                st.error("❌ Por favor complete todos los campos obligatorios (*)")
                return

            if password != password_confirm:
                st.error("❌ Las contraseñas no coinciden")
                return

            # Verificar si el número económico ya existe
            if numero_economico in df['numero_economico'].values:
                st.error("❌ El número económico ya existe")
                return

            # Sanitizar entradas
            numero_economico = sanitize_input(numero_economico)
            nombre_completo = sanitize_input(nombre_completo)
            puesto = sanitize_input(puesto)
            servicio = sanitize_input(servicio)
            turno_laboral = sanitize_input(turno_laboral)
            correo_electronico = sanitize_input(correo_electronico)
            password = sanitize_input(password)

            # Crear nuevo registro para archivo de claves
            nuevo_registro = {
                'numero_economico': numero_economico,
                'puesto': puesto,
                'nombre_completo': nombre_completo,
                'servicio': servicio,
                'turno_laboral': turno_laboral,
                'password': password,
                'correo_electronico': correo_electronico,
                'suplencia': suplencia
            }

            # Agregar a DataFrame
            df = pd.concat([df, pd.DataFrame([nuevo_registro])], ignore_index=True)

            # Guardar archivo de claves
            if guardar_archivo_claves(df):
                st.success("✅ Usuario creado exitosamente en archivo de claves")

                # Crear registro en archivo de asistencia
                if crear_registro_asistencia_manual(numero_economico, hora_entrada, incidencia_codigo, fecha_str, hora_str):
                    st.success("✅ Registro de asistencia creado exitosamente")
                else:
                    st.warning("⚠️ Usuario creado pero hubo un error al crear el registro de asistencia")

                st.rerun()
            else:
                st.error("❌ Error al guardar el usuario")


def mostrar_edicion_claves(user_info):
    """Muestra la interfaz para edición de registros en archivo de claves"""
    st.header("✏️ Edición de Usuarios en Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    if df.empty:
        st.info("No hay usuarios registrados")
        return

    # Selector de usuario a editar
    usuarios_opciones = [f"{row['numero_economico']} - {row['nombre_completo']}" for _, row in df.iterrows()]

    # Usar session_state para mantener la selección del usuario
    if 'usuario_editar_seleccionado' not in st.session_state:
        st.session_state.usuario_editar_seleccionado = usuarios_opciones[0] if usuarios_opciones else None

    usuario_seleccionado = st.selectbox(
        "Seleccione usuario a editar:",
        usuarios_opciones,
        key="usuario_editar",
        index=usuarios_opciones.index(st.session_state.usuario_editar_seleccionado) if st.session_state.usuario_editar_seleccionado in usuarios_opciones else 0
    )

    # Actualizar session_state cuando cambia la selección
    if usuario_seleccionado != st.session_state.get('usuario_editar_seleccionado'):
        st.session_state.usuario_editar_seleccionado = usuario_seleccionado
        st.session_state.usuario_data_actual = None  # Limpiar datos cacheados
        st.rerun()

    if usuario_seleccionado:
        numero_economico_original = usuario_seleccionado.split(" - ")[0]

        # Cargar datos del usuario seleccionado (evitar cache)
        if 'usuario_data_actual' not in st.session_state or st.session_state.get('usuario_numero_actual') != numero_economico_original:
            usuario_data = df[df['numero_economico'] == numero_economico_original].iloc[0]
            st.session_state.usuario_data_actual = usuario_data
            st.session_state.usuario_numero_actual = numero_economico_original
        else:
            usuario_data = st.session_state.usuario_data_actual

        # Mostrar información actual del usuario
        st.subheader("👤 Información Actual del Usuario")
        col_info1, col_info2 = st.columns(2)
        with col_info1:
            st.info(f"**Número Económico:** {usuario_data['numero_economico']}")
            st.info(f"**Nombre:** {usuario_data['nombre_completo']}")
            st.info(f"**Puesto:** {usuario_data['puesto']}")
        with col_info2:
            st.info(f"**Servicio:** {usuario_data['servicio']}")
            st.info(f"**Turno:** {usuario_data['turno_laboral']}")
            st.info(f"**Suplencia:** {usuario_data['suplencia']}")

        with st.form("form_edicion_claves"):
            st.subheader("✏️ Modificar Datos del Usuario")

            col1, col2 = st.columns(2)

            with col1:
                # Encontrar índices actuales para los selectboxes
                puesto_index = CONFIG.PUESTOS.index(usuario_data['puesto']) if usuario_data['puesto'] in CONFIG.PUESTOS else 0
                servicio_index = CONFIG.SERVICIOS.index(usuario_data['servicio']) if usuario_data['servicio'] in CONFIG.SERVICIOS else 0
                turno_index = CONFIG.TURNOS.index(usuario_data['turno_laboral']) if usuario_data['turno_laboral'] in CONFIG.TURNOS else 0
                suplencia_index = CONFIG.SUPLENCIA_OPCIONES.index(usuario_data['suplencia']) if usuario_data['suplencia'] in CONFIG.SUPLENCIA_OPCIONES else 1

                nuevo_numero_economico = st.text_input(
                    "Número Económico*",
                    value=usuario_data['numero_economico'],
                    max_chars=10,
                    key=f"num_economico_edit_{numero_economico_original}"
                )
                nuevo_puesto = st.selectbox(
                    "Puesto*",
                    options=CONFIG.PUESTOS,
                    index=puesto_index,
                    key=f"puesto_select_edit_{numero_economico_original}"
                )
                nuevo_servicio = st.selectbox(
                    "Servicio*",
                    options=CONFIG.SERVICIOS,
                    index=servicio_index,
                    key=f"servicio_select_edit_{numero_economico_original}"
                )
                nuevo_turno_laboral = st.selectbox(
                    "🕒 Turno laboral*",
                    options=CONFIG.TURNOS,
                    index=turno_index,
                    key=f"turno_select_edit_{numero_economico_original}"
                )

            with col2:
                nuevo_nombre_completo = st.text_input(
                    "Nombre Completo*",
                    value=usuario_data['nombre_completo'],
                    key=f"nombre_completo_edit_{numero_economico_original}"
                )
                nuevo_correo_electronico = st.text_input(
                    "Correo Electrónico",
                    value=usuario_data.get('correo_electronico', ''),
                    key=f"correo_edit_{numero_economico_original}"
                )
                nueva_suplencia = st.selectbox(
                    "Suplencia*",
                    options=CONFIG.SUPLENCIA_OPCIONES,
                    index=suplencia_index,
                    key=f"suplencia_select_edit_{numero_economico_original}"
                )
                nueva_password = st.text_input(
                    "Nueva Contraseña (dejar vacío para mantener actual)",
                    type="password",
                    key=f"password_edit_{numero_economico_original}"
                )
                confirmar_password = st.text_input(
                    "Confirmar Nueva Contraseña",
                    type="password",
                    key=f"password_confirm_edit_{numero_economico_original}"
                )

            # Campos adicionales para asistencia
            st.markdown("---")
            st.subheader("📋 Actualización de Datos de Asistencia")

            col3, col4 = st.columns(2)

            with col3:
                # Selector de fecha y hora personalizada
                st.subheader("🗓️ Fecha y Hora del Registro")
                fecha_personalizada = st.date_input(
                    "Fecha*",
                    value=datetime.now().date(),
                    key=f"fecha_personalizada_edicion_{numero_economico_original}"
                )

                hora_personalizada = st.time_input(
                    "Hora*",
                    value=datetime.now().time(),
                    key=f"hora_personalizada_edicion_{numero_economico_original}"
                )

                # Convertir a string en el formato requerido
                fecha_str = fecha_personalizada.strftime("%Y-%m-%d")
                hora_str = hora_personalizada.strftime("%H:%M")
                fecha_completa_str = f"{fecha_str} {hora_str}"

                st.info(f"**Fecha completa:** {fecha_completa_str}")
                st.info(f"**Fecha del turno:** {fecha_str}")

            with col4:
                # Cargar datos actuales de asistencia para este usuario
                df_asistencia = cargar_archivo_asistencia()
                hora_entrada_actual = "NO"
                incidencia_actual = "NO"

                if df_asistencia is not None and not df_asistencia.empty:
                    registro_asistencia = df_asistencia[
                        (df_asistencia['numero_economico'] == numero_economico_original) &
                        (df_asistencia['fecha_turno'] == fecha_str)
                    ]
                    if not registro_asistencia.empty:
                        registro = registro_asistencia.iloc[0]
                        hora_entrada_actual = registro['hora_entrada'] if pd.notna(registro['hora_entrada']) and registro['hora_entrada'] != '' else "NO"
                        incidencia_actual = registro['incidencias'] if pd.notna(registro['incidencias']) and registro['incidencias'] != '' else "NO"

                # Encontrar índice actual para hora_entrada
                hora_entrada_index = 0
                if hora_entrada_actual in CONFIG.HORAS_ENTRADA:
                    hora_entrada_index = CONFIG.HORAS_ENTRADA.index(hora_entrada_actual)

                nueva_hora_entrada = st.selectbox(
                    "Hora de Entrada*",
                    options=CONFIG.HORAS_ENTRADA,
                    index=hora_entrada_index,
                    key=f"hora_entrada_edit_{numero_economico_original}"
                )

                # Crear opciones para incidencias
                opciones_incidencias = ["NO"] + [f"{codigo} - {descripcion}" for codigo, descripcion in CONFIG.INCIDENCIAS.items()]

                # Encontrar índice actual para incidencias
                incidencia_index = 0
                if incidencia_actual != "NO":
                    # Buscar la incidencia actual en las opciones
                    for i, opcion in enumerate(opciones_incidencias):
                        if opcion.startswith(incidencia_actual):
                            incidencia_index = i
                            break

                nueva_incidencia_seleccionada = st.selectbox(
                    "Incidencias*",
                    options=opciones_incidencias,
                    index=incidencia_index,
                    key=f"incidencia_select_edit_{numero_economico_original}"
                )

                # Extraer solo el código de la incidencia si se seleccionó algo diferente a "NO"
                nueva_incidencia_codigo = "NO"
                if nueva_incidencia_seleccionada != "NO":
                    nueva_incidencia_codigo = nueva_incidencia_seleccionada.split(" - ")[0]

            submitted = st.form_submit_button("✅ Actualizar Usuario y Registro de Asistencia")

            if submitted:
                # Validaciones
                if not all([nuevo_numero_economico, nuevo_nombre_completo, nuevo_puesto, nuevo_servicio, nuevo_turno_laboral]):
                    st.error("❌ Por favor complete todos los campos obligatorios (*)")
                    return

                if nueva_password and nueva_password != confirmar_password:
                    st.error("❌ Las contraseñas no coinciden")
                    return

                # Verificar si el nuevo número económico ya existe (si se cambió)
                if (nuevo_numero_economico != numero_economico_original and
                    nuevo_numero_economico in df['numero_economico'].values):
                    st.error("❌ El nuevo número económico ya existe")
                    return

                # Sanitizar entradas
                nuevo_numero_economico = sanitize_input(nuevo_numero_economico)
                nuevo_nombre_completo = sanitize_input(nuevo_nombre_completo)
                nuevo_puesto = sanitize_input(nuevo_puesto)
                nuevo_servicio = sanitize_input(nuevo_servicio)
                nuevo_turno_laboral = sanitize_input(nuevo_turno_laboral)
                nuevo_correo_electronico = sanitize_input(nuevo_correo_electronico)

                # Actualizar datos en DataFrame
                mask = df['numero_economico'] == numero_economico_original
                df.loc[mask, 'numero_economico'] = nuevo_numero_economico
                df.loc[mask, 'nombre_completo'] = nuevo_nombre_completo
                df.loc[mask, 'puesto'] = nuevo_puesto
                df.loc[mask, 'servicio'] = nuevo_servicio
                df.loc[mask, 'turno_laboral'] = nuevo_turno_laboral
                df.loc[mask, 'correo_electronico'] = nuevo_correo_electronico
                df.loc[mask, 'suplencia'] = nueva_suplencia

                # Actualizar contraseña si se proporcionó una nueva
                if nueva_password:
                    df.loc[mask, 'password'] = nueva_password

                # Guardar archivo de claves
                if guardar_archivo_claves(df):
                    st.success("✅ Usuario actualizado exitosamente en archivo de claves")

                    # Actualizar registro en archivo de asistencia
                    if actualizar_registro_asistencia_manual(
                        numero_economico_original,
                        nuevo_numero_economico,
                        nueva_hora_entrada,
                        nueva_incidencia_codigo,
                        fecha_str,
                        hora_str
                    ):
                        st.success("✅ Registro de asistencia actualizado exitosamente")
                    else:
                        st.warning("⚠️ Usuario actualizado pero hubo un error al actualizar el registro de asistencia")

                    # Limpiar selección y datos cacheados para forzar recarga
                    if 'usuario_editar_seleccionado' in st.session_state:
                        del st.session_state.usuario_editar_seleccionado
                    if 'usuario_data_actual' in st.session_state:
                        del st.session_state.usuario_data_actual
                    if 'usuario_numero_actual' in st.session_state:
                        del st.session_state.usuario_numero_actual
                    st.rerun()
                else:
                    st.error("❌ Error al actualizar el usuario")

def mostrar_eliminacion_claves(user_info):
    """Muestra la interfaz para eliminación de registros en archivo de claves"""
    st.header("🗑️ Eliminación de Usuarios en Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    if df.empty:
        st.info("No hay usuarios registrados")
        return

    # Selector de usuario a eliminar
    usuarios_opciones = [f"{row['numero_economico']} - {row['nombre_completo']}" for _, row in df.iterrows()]
    
    # Usar session_state para mantener la selección del usuario
    if 'usuario_eliminar_seleccionado' not in st.session_state:
        st.session_state.usuario_eliminar_seleccionado = usuarios_opciones[0] if usuarios_opciones else None

    usuario_seleccionado = st.selectbox(
        "Seleccione usuario a eliminar:", 
        usuarios_opciones, 
        key="usuario_eliminar",
        index=usuarios_opciones.index(st.session_state.usuario_eliminar_seleccionado) if st.session_state.usuario_eliminar_seleccionado in usuarios_opciones else 0
    )

    # Actualizar session_state cuando cambia la selección
    if usuario_seleccionado != st.session_state.get('usuario_eliminar_seleccionado'):
        st.session_state.usuario_eliminar_seleccionado = usuario_seleccionado
        st.rerun()

    if usuario_seleccionado:
        numero_economico_eliminar = usuario_seleccionado.split(" - ")[0]
        usuario_data = df[df['numero_economico'] == numero_economico_eliminar].iloc[0]

        # Mostrar información del usuario
        st.warning(f"⚠️ Está a punto de eliminar al siguiente usuario:")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Número Económico:** {usuario_data['numero_economico']}")
            st.write(f"**Nombre:** {usuario_data['nombre_completo']}")
            st.write(f"**Puesto:** {usuario_data['puesto']}")
        with col2:
            st.write(f"**Servicio:** {usuario_data['servicio']}")
            st.write(f"**Turno:** {usuario_data['turno_laboral']}")
            st.write(f"**Suplencia:** {usuario_data['suplencia']}")

        # Campos adicionales para asistencia
        st.markdown("---")
        st.subheader("📋 Eliminación de Registro de Asistencia")
        
        col3, col4 = st.columns(2)
        
        with col3:
            # Selector de fecha para eliminar registro de asistencia
            fecha_eliminacion = st.date_input(
                "Fecha del turno a eliminar*",
                value=datetime.now().date(),
                key="fecha_eliminacion_asistencia"
            )
            fecha_turno_str = fecha_eliminacion.strftime("%Y-%m-%d")
            st.info(f"**Fecha del turno:** {fecha_turno_str}")
            
        with col4:
            # Mostrar información del registro de asistencia que se eliminará
            df_asistencia = cargar_archivo_asistencia()
            if df_asistencia is not None and not df_asistencia.empty:
                registro_asistencia = df_asistencia[
                    (df_asistencia['numero_economico'] == numero_economico_eliminar) & 
                    (df_asistencia['fecha_turno'] == fecha_turno_str)
                ]
                if not registro_asistencia.empty:
                    st.warning("Se eliminará el siguiente registro de asistencia:")
                    st.write(f"**Hora de entrada:** {registro_asistencia.iloc[0]['hora_entrada']}")
                    st.write(f"**Incidencias:** {registro_asistencia.iloc[0]['incidencias']}")
                else:
                    st.info("No hay registro de asistencia para esta fecha")
            else:
                st.info("No hay registros de asistencia")

        # Confirmación de eliminación
        confirmacion = st.checkbox("✅ Confirmo que deseo eliminar este usuario y su registro de asistencia", key="confirm_eliminar")

        if st.button("🗑️ Eliminar Usuario y Registro de Asistencia", type="secondary"):
            if not confirmacion:
                st.error("❌ Debe confirmar la eliminación")
                return

            try:
                # Eliminar usuario del archivo de claves
                df_actualizado = df[df['numero_economico'] != numero_economico_eliminar]

                if guardar_archivo_claves(df_actualizado):
                    st.success("✅ Usuario eliminado exitosamente del archivo de claves")

                    # Sincronizar eliminación con archivo de asistencia
                    if sincronizar_baja_asistencia(numero_economico_eliminar, fecha_turno_str):
                        st.success("✅ Registro de asistencia eliminado exitosamente")
                    else:
                        st.warning("⚠️ Usuario eliminado pero hubo un error al eliminar el registro de asistencia")

                    # Limpiar selección para forzar recarga
                    if 'usuario_eliminar_seleccionado' in st.session_state:
                        del st.session_state.usuario_eliminar_seleccionado
                    st.rerun()
                else:
                    st.error("❌ Error al eliminar el usuario")

            except Exception as e:
                st.error(f"❌ Error durante la eliminación: {str(e)}")

def mostrar_consulta_claves(user_info):
    """Muestra la interfaz para consulta de registros en archivo de claves"""
    st.header("🔍 Consulta de Archivo de Claves")

    # Cargar datos existentes
    df = cargar_archivo_claves()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    if df.empty:
        st.info("No hay usuarios registrados")
        return

    # Filtros de búsqueda
    col1, col2, col3 = st.columns(3)
    with col1:
        filtro_numero = st.text_input("Filtrar por número económico", key="filtro_numero")
    with col2:
        filtro_nombre = st.text_input("Filtrar por nombre", key="filtro_nombre")
    with col3:
        filtro_servicio = st.selectbox(
            "Filtrar por servicio",
            options=["Todos"] + CONFIG.SERVICIOS,
            key="filtro_servicio"
        )

    # Aplicar filtros
    df_filtrado = df.copy()
    if filtro_numero:
        df_filtrado = df_filtrado[df_filtrado['numero_economico'].str.contains(filtro_numero, case=False, na=False)]
    if filtro_nombre:
        df_filtrado = df_filtrado[df_filtrado['nombre_completo'].str.contains(filtro_nombre, case=False, na=False)]
    if filtro_servicio != "Todos":
        df_filtrado = df_filtrado[df_filtrado['servicio'] == filtro_servicio]

    # Mostrar resultados
    st.subheader(f"📊 Resultados ({len(df_filtrado)} usuarios)")

    if not df_filtrado.empty:
        # Seleccionar columnas a mostrar (excluir contraseña)
        columnas_mostrar = ['numero_economico', 'nombre_completo', 'puesto', 'servicio', 'turno_laboral', 'suplencia']
        if 'correo_electronico' in df_filtrado.columns:
            columnas_mostrar.append('correo_electronico')

        df_mostrar = df_filtrado[columnas_mostrar]

        # Formatear datos para mejor visualización
        df_mostrar['puesto'] = df_mostrar['puesto'].str.title()
        df_mostrar['suplencia'] = df_mostrar['suplencia'].str.upper()

        st.dataframe(df_mostrar, use_container_width=True)

        # Opción de descarga
        csv = df_mostrar.to_csv(index=False)
        st.download_button(
            label="📥 Descargar consulta como CSV",
            data=csv,
            file_name=f"consulta_claves_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No se encontraron usuarios con los filtros aplicados")

def mostrar_consulta_asistencia(user_info):
    """Muestra la interfaz para consulta de registros en archivo de asistencia"""
    st.header("📋 Consulta de Archivo de Asistencia")

    # Cargar datos existentes
    df = cargar_archivo_asistencia()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    if df.empty:
        st.info("No hay registros de asistencia")
        return

    # Filtros de búsqueda
    col1, col2, col3 = st.columns(3)
    with col1:
        filtro_numero = st.text_input("Filtrar por número económico", key="filtro_numero_asistencia")
    with col2:
        filtro_nombre = st.text_input("Filtrar por nombre", key="filtro_nombre_asistencia")
    with col3:
        filtro_fecha = st.date_input("Filtrar por fecha de turno", key="filtro_fecha_asistencia")

    # Aplicar filtros
    df_filtrado = df.copy()
    if filtro_numero:
        df_filtrado = df_filtrado[df_filtrado['numero_economico'].str.contains(filtro_numero, case=False, na=False)]
    if filtro_nombre:
        df_filtrado = df_filtrado[df_filtrado['nombre_completo'].str.contains(filtro_nombre, case=False, na=False)]
    if filtro_fecha:
        fecha_str = filtro_fecha.strftime("%Y-%m-%d")
        df_filtrado = df_filtrado[df_filtrado['fecha_turno'] == fecha_str]

    # Mostrar resultados
    st.subheader(f"📊 Resultados ({len(df_filtrado)} registros)")

    if not df_filtrado.empty:
        # Seleccionar columnas a mostrar
        columnas_mostrar = ['fecha', 'fecha_turno', 'numero_economico', 'nombre_completo', 'puesto', 
                          'servicio', 'turno_laboral', 'hora_entrada', 'incidencias', 'suplencia']

        df_mostrar = df_filtrado[columnas_mostrar]

        # Formatear datos para mejor visualización
        df_mostrar['puesto'] = df_mostrar['puesto'].str.title()
        df_mostrar['suplencia'] = df_mostrar['suplencia'].str.upper()

        st.dataframe(df_mostrar, use_container_width=True)

        # Opción de descarga
        csv = df_mostrar.to_csv(index=False)
        st.download_button(
            label="📥 Descargar consulta como CSV",
            data=csv,
            file_name=f"consulta_asistencia_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No se encontraron registros con los filtros aplicados")

def generar_reporte_pdf(user_info):
    """Genera un reporte en PDF con los datos de asistencia"""
    st.header("📄 Generar Reporte PDF de Asistencia")

    # Cargar datos existentes
    df = cargar_archivo_asistencia()
    if df is None:
        st.error("No se pudieron cargar los datos existentes")
        return

    if df.empty:
        st.info("No hay registros de asistencia para generar reporte")
        return

    # Filtros para el reporte
    col1, col2 = st.columns(2)
    with col1:
        fecha_inicio = st.date_input("Fecha de inicio", key="fecha_inicio_reporte")
    with col2:
        fecha_fin = st.date_input("Fecha de fin", key="fecha_fin_reporte")

    # Filtrar datos por fecha
    if fecha_inicio and fecha_fin:
        if fecha_inicio > fecha_fin:
            st.error("❌ La fecha de inicio no puede ser mayor a la fecha de fin")
            return

        fecha_inicio_str = fecha_inicio.strftime("%Y-%m-%d")
        fecha_fin_str = fecha_fin.strftime("%Y-%m-%d")

        df_filtrado = df[
            (df['fecha_turno'] >= fecha_inicio_str) & 
            (df['fecha_turno'] <= fecha_fin_str)
        ]
    else:
        df_filtrado = df

    if df_filtrado.empty:
        st.info("No hay registros en el rango de fechas seleccionado")
        return

    st.info(f"📊 Se generará reporte con {len(df_filtrado)} registros")

    if st.button("🖨️ Generar Reporte PDF"):
        try:
            # Crear PDF
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            elements = []

            # Estilos
            styles = getSampleStyleSheet()
            style_normal = styles['Normal']
            style_heading = styles['Heading1']

            # Título
            title = Paragraph(f"Reporte de Asistencia - {fecha_inicio_str} a {fecha_fin_str}", style_heading)
            elements.append(title)
            elements.append(Spacer(1, 12))

            # Preparar datos para la tabla
            datos_tabla = [['Fecha', 'Núm. Econ.', 'Nombre', 'Puesto', 'Servicio', 'Turno', 'Hora Entrada', 'Incidencias']]

            for _, row in df_filtrado.iterrows():
                datos_tabla.append([
                    row['fecha_turno'],
                    row['numero_economico'],
                    row['nombre_completo'],
                    row['puesto'].title(),
                    row['servicio'],
                    row['turno_laboral'],
                    row['hora_entrada'],
                    row['incidencias']
                ])

            # Crear tabla
            tabla = Table(datos_tabla)
            tabla.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            elements.append(tabla)

            # Generar PDF
            doc.build(elements)
            pdf_data = buffer.getvalue()
            buffer.close()

            # Descargar PDF
            st.download_button(
                label="📥 Descargar Reporte PDF",
                data=pdf_data,
                file_name=f"reporte_asistencia_{fecha_inicio_str}_a_{fecha_fin_str}.pdf",
                mime="application/pdf"
            )

        except Exception as e:
            st.error(f"❌ Error generando PDF: {str(e)}")

# ====================
# FUNCIÓN PRINCIPAL
# ====================
def main():
    # Configuración de la página
    st.set_page_config(
        page_title="Sistema de Administración - Archivo de Claves",
        page_icon="🏥",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Verificar autenticación
    authenticated, user_info = authenticate_user()

    if not authenticated:
        return

    # Mostrar información del usuario autenticado
    st.sidebar.title("👤 Información del Usuario")
    st.sidebar.write(f"**Número Económico:** {user_info['numero_economico']}")
    st.sidebar.write(f"**Nombre:** {user_info['nombre_completo']}")
    st.sidebar.write(f"**Puesto:** {user_info['puesto']}")
    if user_info.get('turno_laboral'):
        st.sidebar.write(f"**Turno:** {user_info['turno_laboral']}")

    st.sidebar.markdown("---")

    # Menú de navegación
    st.sidebar.title("📋 Menú de Navegación")
    opcion = st.sidebar.radio(
        "Seleccione una opción:",
        [
            "📝 Creación de Usuarios",
            "✏️ Edición de Usuarios", 
            "🗑️ Eliminación de Usuarios",
            "🔍 Consulta de Claves",
            "📋 Consulta de Asistencia",
            "📄 Generar Reporte PDF"
        ]
    )

    # Navegación entre páginas
    if opcion == "📝 Creación de Usuarios":
        mostrar_creacion_claves(user_info)
    elif opcion == "✏️ Edición de Usuarios":
        mostrar_edicion_claves(user_info)
    elif opcion == "🗑️ Eliminación de Usuarios":
        mostrar_eliminacion_claves(user_info)
    elif opcion == "🔍 Consulta de Claves":
        mostrar_consulta_claves(user_info)
    elif opcion == "📋 Consulta de Asistencia":
        mostrar_consulta_asistencia(user_info)
    elif opcion == "📄 Generar Reporte PDF":
        generar_reporte_pdf(user_info)

    # Información de debug (solo si está activado)
    if CONFIG.DEBUG_MODE:
        st.sidebar.markdown("---")
        st.sidebar.title("🐛 Debug Info")
        st.sidebar.write(f"Usuario: {user_info}")
        st.sidebar.write(f"Archivo claves: {CONFIG.FILES['claves']}")
        st.sidebar.write(f"Archivo asistencia: {CONFIG.FILES['asistencia']}")

    # Cerrar sesión
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Cerrar Sesión"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

if __name__ == "__main__":
    main()
