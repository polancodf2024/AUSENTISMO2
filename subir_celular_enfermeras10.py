import streamlit as st
import datetime
import json
import os
import pandas as pd
import paramiko
import csv
import io
import time
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import pytz  # IMPORTACIÓN AGREGADA PARA ZONA HORARIA

# Configuración de la página
st.set_page_config(
    page_title="Sistema de Registro de Enfermería",
    page_icon="🏥",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Ocultar el sidebar completamente y aplicar estilos
st.markdown("""
    <style>
        section[data-testid="stSidebar"] {
            display: none !important;
        }
        .main > div {
            padding-top: 1rem;
        }
        .stButton > button {
            width: 100%;
            height: 3rem;
            font-size: 1.1rem;
            margin: 0.3rem 0;
        }
        .stTextInput > div > div > input {
            font-size: 1.1rem;
            height: 2.5rem;
        }
        .info-box {
            padding: 1.2rem;
            background-color: #e8f4fd;
            border-radius: 0.8rem;
            border: 2px solid #0078d4;
            margin: 1rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .success-box {
            padding: 1.2rem;
            background-color: #d4edda;
            border-radius: 0.8rem;
            border: 2px solid #28a745;
            margin: 1rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header-text {
            color: #0078d4;
            text-align: center;
            margin-bottom: 1rem;
        }
        .password-requirements {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 0.5rem;
            padding: 1rem;
            margin: 0.5rem 0;
            font-size: 0.9rem;
        }
        .password-error {
            color: #dc3545;
            font-size: 0.85rem;
            margin-top: 0.25rem;
        }
        .password-success {
            color: #28a745;
            font-size: 0.85rem;
            margin-top: 0.25rem;
        }
        .field-error {
            border: 1px solid #dc3545 !important;
            background-color: #f8d7da !important;
        }
        .incidencia-section {
            background-color: #f8f9fa;
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin: 1rem 0;
            border: 2px solid #ffc107;
        }
        .incidencia-option {
            padding: 0.5rem;
            margin: 0.25rem 0;
            border-radius: 0.3rem;
            border-left: 4px solid #0078d4;
            background-color: #f8f9fa;
        }
    </style>
""", unsafe_allow_html=True)

class SistemaAsistencia:
    def __init__(self):
        # CORREGIDO: Usar zona horaria de Ciudad de México
        mexico_tz = pytz.timezone('America/Mexico_City')
        fecha_mexico = datetime.datetime.now(mexico_tz).date()
        self.archivo_asistencia = f"asistencia_{fecha_mexico.strftime('%Y%m%d')}.csv"
        self.crear_archivo_si_no_existe()
    
    def crear_archivo_si_no_existe(self):
        """Crear archivo de asistencia si no existe"""
        if not Path(self.archivo_asistencia).exists():
            pd.DataFrame(columns=[
                'FECHA', 'HORA', 'NOMBRE_COMPLETO', 'PUESTO', 
                'TURNO', 'TIPO_REGISTRO', 'PASSWORD_USADA'
            ]).to_csv(self.archivo_asistencia, index=False)
    
    def obtener_informacion_empleado(self, usuario):
        """Obtener información del usuario"""
        return {
            'nombre_completo': usuario['nombre_completo'],
            'puesto': usuario['puesto'],
            'turno': usuario['turno_laboral']
        }
    
    def obtener_fecha_hora_actual_mexico(self):
        """CORREGIDO: Obtiene la fecha y hora actual en la zona horaria de Ciudad de México"""
        mexico_tz = pytz.timezone('America/Mexico_City')
        ahora_mexico = datetime.datetime.now(mexico_tz)
        return ahora_mexico
    
    def registrar_asistencia(self, tipo_registro, usuario, password_usada):
        """CORREGIDO: Registrar la asistencia con hora de Ciudad de México"""
        try:
            empleado = self.obtener_informacion_empleado(usuario)
            
            # CORREGIDO: USAR HORA DE CIUDAD DE MÉXICO
            ahora_mexico = self.obtener_fecha_hora_actual_mexico()
            
            nuevo_registro = {
                'FECHA': ahora_mexico.strftime('%Y-%m-%d'),
                'HORA': ahora_mexico.strftime('%H:%M:%S'),
                'NOMBRE_COMPLETO': empleado['nombre_completo'],
                'PUESTO': empleado['puesto'],
                'TURNO': empleado['turno'],
                'TIPO_REGISTRO': tipo_registro,
                'PASSWORD_USADA': password_usada
            }
            
            df = pd.read_csv(self.archivo_asistencia)
            df = pd.concat([df, pd.DataFrame([nuevo_registro])], ignore_index=True)
            df.to_csv(self.archivo_asistencia, index=False)
            return True, nuevo_registro
        except Exception as e:
            return False, str(e)
    
    def obtener_tipo_registro(self, usuario):
        """CORREGIDO: Determinar si es entrada o salida basado en registros previos usando hora de México"""
        try:
            df = pd.read_csv(self.archivo_asistencia)
            if df.empty:
                return "ENTRADA"
            
            # CORREGIDO: USAR FECHA DE CIUDAD DE MÉXICO
            mexico_tz = pytz.timezone('America/Mexico_City')
            hoy_mexico = datetime.datetime.now(mexico_tz).date().strftime('%Y-%m-%d')
            
            # Buscar registros de hoy para este usuario
            registros_hoy = df[(df['FECHA'] == hoy_mexico) & 
                             (df['NOMBRE_COMPLETO'] == usuario['nombre_completo'])]
            
            if registros_hoy.empty:
                return "ENTRADA"
            
            # Si el último registro fue ENTRADA, ahora es SALIDA
            ultimo_registro = registros_hoy.iloc[-1]
            return "SALIDA" if ultimo_registro['TIPO_REGISTRO'] == "ENTRADA" else "ENTRADA"
            
        except:
            return "ENTRADA"
    
    def obtener_registros_hoy_usuario(self, usuario):
        """CORREGIDO: Obtener todos los registros de hoy para el usuario usando fecha de México"""
        try:
            df = pd.read_csv(self.archivo_asistencia)
            
            # CORREGIDO: USAR FECHA DE CIUDAD DE MÉXICO
            mexico_tz = pytz.timezone('America/Mexico_City')
            hoy_mexico = datetime.datetime.now(mexico_tz).date().strftime('%Y-%m-%d')
            
            return df[(df['FECHA'] == hoy_mexico) & 
                     (df['NOMBRE_COMPLETO'] == usuario['nombre_completo'])]
        except:
            return pd.DataFrame()

class SistemaCorreo:
    def __init__(self):
        self.smtp_server = st.secrets["smtp_server"]
        self.smtp_port = st.secrets["smtp_port"]
        self.email_user = st.secrets["email_user"]
        self.email_password = st.secrets["email_password"]
        self.notification_email = st.secrets["notification_email"]
    
    def obtener_fecha_hora_actual_mexico(self):
        """CORREGIDO: Obtiene la fecha y hora actual en la zona horaria de Ciudad de México"""
        mexico_tz = pytz.timezone('America/Mexico_City')
        ahora_mexico = datetime.datetime.now(mexico_tz)
        return ahora_mexico
    
    def enviar_correo_confirmacion(self, destinatario, datos_registro):
        """CORREGIDO: Envía un correo de confirmación de asistencia con hora de México"""
        try:
            # Crear el mensaje
            msg = MIMEMultipart()
            msg['From'] = self.email_user
            msg['To'] = destinatario
            msg['Subject'] = "Confirmación de Registro de Asistencia - Sistema de Enfermería"
            
            # CORREGIDO: USAR FECHA Y HORA DE CIUDAD DE MÉXICO
            ahora_mexico = self.obtener_fecha_hora_actual_mexico()
            
            # Crear el cuerpo del mensaje
            cuerpo = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <h2 style="color: #0078d4;">🏥 Confirmación de Registro de Asistencia</h2>
                
                <p>Se ha registrado exitosamente su asistencia en el sistema:</p>
                
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #0078d4;">
                    <h3 style="margin-top: 0; color: #0078d4;">📋 Detalles del Registro</h3>
                    <p><strong>Nombre:</strong> {datos_registro['nombre_completo']}</p>
                    <p><strong>Puesto:</strong> {datos_registro['puesto']}</p>
                    <p><strong>Servicio:</strong> {datos_registro['servicio']}</p>
                    <p><strong>Turno:</strong> {datos_registro['turno_laboral']}</p>
                    <p><strong>Fecha:</strong> {datos_registro['fecha']}</p>
                    <p><strong>Hora de registro:</strong> {datos_registro['hora_registro']}</p>
                    <p><strong>Tipo de registro:</strong> {datos_registro['tipo_registro']}</p>
                    <p><strong>Incidencia:</strong> {datos_registro.get('incidencia', 'NO')}</p>
                    <p><strong>Suplencia:</strong> {datos_registro.get('suplencia', 'NO')}</p>
                    <p><strong>Zona horaria:</strong> Ciudad de México</p>
                </div>
                
                <p style="margin-top: 20px;">
                    <strong>📍 Método de registro:</strong> Sistema Web de Enfermería
                </p>
                
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                
                <p style="font-size: 12px; color: #666;">
                    Este es un mensaje automático. Por favor no responda a este correo.<br>
                    Sistema de Registro de Enfermería - {ahora_mexico.year}
                </p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(cuerpo, 'html'))
            
            # Enviar el correo
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_user, self.email_password)
            text = msg.as_string()
            server.sendmail(self.email_user, destinatario, text)
            server.quit()
            
            return True, "Correo enviado exitosamente"
            
        except Exception as e:
            return False, f"Error al enviar correo: {str(e)}"

class SistemaEnfermeria:
    def __init__(self):
        # ACTUALIZADO: Servicios según el archivo Excel proporcionado
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
        
        self.PUESTOS = [
            "enfermera general A",
            "enfermera general B",
            "enfermera general C",
            "enfermera especialista",
            "ayudante general",
            "camillero",
            "jefatura servicio",
            "jefatura departamento",
            "supervision turno"
        ]
        
        self.TURNOS = [
            "Matutino (7:00-15:00)",
            "Vespertino (14:30-21:00)",
            "Nocturno (A y B) (20:30-8:00)",
            "Jornada Acumulada (8:00-20:00)"
        ]
        
        # NUEVA TABLA DE INCIDENCIAS CON DESCRIPCIONES
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
        
        # Configuración de conexión remota desde secrets.toml
        self.remote_config = {
            'host': st.secrets["remote_host"],
            'username': st.secrets["remote_user"],
            'password': st.secrets["remote_password"],
            'port': st.secrets["remote_port"],
            'remote_dir': st.secrets["remote_dir"],
            'file_creacion_enfermeras2': st.secrets["file_creacion_enfermeras2"],
            'file_asistencia_enfermeras2': st.secrets["file_enfermeras2"],
            'file_historico_enfermeras2': st.secrets["file_historico_enfermeras2"]
        }
        
        self.TURNOS_NOCTURNOS = ["Nocturno (A y B) (20:30-8:00)"]
        
        # ELIMINADO: archivos locales
        self.sistema_asistencia = SistemaAsistencia()
        self.sistema_correo = SistemaCorreo()

    def obtener_fecha_hora_actual_mexico(self):
        """CORREGIDO: Obtiene la fecha y hora actual en la zona horaria de Ciudad de México"""
        mexico_tz = pytz.timezone('America/Mexico_City')
        ahora_mexico = datetime.datetime.now(mexico_tz)
        return ahora_mexico

    def conectar_ssh(self):
        """Establece conexión SSH con el servidor remoto"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                self.remote_config['host'],
                port=self.remote_config['port'],
                username=self.remote_config['username'],
                password=self.remote_config['password']
            )
            return ssh
        except Exception as e:
            st.error(f"❌ Error al conectar con el servidor remoto: {e}")
            return None

    def verificar_password_remoto(self, password):
        """Verifica si la contraseña ya existe en el archivo remoto"""
        ssh = self.conectar_ssh()
        if not ssh:
            return False, "No se pudo conectar al servidor para verificar la contraseña"
        
        try:
            sftp = ssh.open_sftp()
            remote_file_path = f"{self.remote_config['remote_dir']}/{self.remote_config['file_creacion_enfermeras2']}"
            
            # Verificar si el archivo existe
            try:
                with sftp.file(remote_file_path, 'r') as archivo_remoto:
                    contenido = archivo_remoto.read().decode('utf-8')
            except:
                contenido = ""
            
            sftp.close()
            ssh.close()
            
            if not contenido.strip():
                return False, "Contraseña disponible (archivo remoto vacío)"
            
            # Leer el archivo CSV y buscar la contraseña
            try:
                df = pd.read_csv(io.StringIO(contenido))
                
                # Verificar si la contraseña ya existe (columna 6, índice 5)
                if not df.empty and len(df.columns) > 5:
                    if password in df.iloc[:, 5].values:
                        return True, "Esta contraseña ya está registrada en el sistema remoto"
                
                return False, "Contraseña disponible"
                
            except Exception as e:
                return False, f"Error al leer archivo remoto: {str(e)}"
                
        except Exception as e:
            try:
                sftp.close()
            except:
                pass
            try:
                ssh.close()
            except:
                pass
            return False, f"Error al verificar contraseña: {str(e)}"

    def validar_numero_economico(self, numero):
        """Valida que el número económico sea único en archivo remoto"""
        # Verificar remotamente en aus_creacion_enfermeras2.csv
        ssh = self.conectar_ssh()
        if not ssh:
            return False
        
        try:
            sftp = ssh.open_sftp()
            remote_file_path = f"{self.remote_config['remote_dir']}/{self.remote_config['file_creacion_enfermeras2']}"
            
            # Verificar si el archivo existe
            try:
                with sftp.file(remote_file_path, 'r') as archivo_remoto:
                    contenido = archivo_remoto.read().decode('utf-8')
            except:
                contenido = ""
            
            sftp.close()
            ssh.close()
            
            if not contenido.strip():
                return True  # Archivo vacío, número disponible
            
            # Leer el archivo CSV y buscar el número económico
            df = pd.read_csv(io.StringIO(contenido))
            
            # Verificar si el número económico ya existe (columna 1, índice 0)
            if not df.empty and len(df.columns) > 0:
                # Convertir a string para comparación consistente
                numero_str = str(numero)
                if numero_str in df.iloc[:, 0].astype(str).values:
                    return False  # Número ya existe
            
            return True  # Número disponible
            
        except Exception as e:
            try:
                sftp.close()
            except:
                pass
            try:
                ssh.close()
            except:
                pass
            return False

    def agregar_registro_remoto(self, datos_usuario):
        """Agrega un registro al archivo remoto aus_creacion_enfermeras2.csv con los nuevos campos"""
        ssh = self.conectar_ssh()
        if not ssh:
            st.error("❌ No se pudo conectar al servidor remoto.")
            return False
        
        try:
            sftp = ssh.open_sftp()
            remote_file_path = f"{self.remote_config['remote_dir']}/{self.remote_config['file_creacion_enfermeras2']}"
            
            # Preparar los datos en formato CSV con los NUEVOS CAMPOS
            fila_csv = [
                datos_usuario['numero_economico'],
                datos_usuario['puesto'],
                datos_usuario['nombre_completo'],
                datos_usuario['servicio'],
                datos_usuario['turno_laboral'],
                datos_usuario['password'],
                datos_usuario.get('correo_electronico', ''),  # Campo de correo
                datos_usuario.get('suplencia', 'NO')  # NUEVO CAMPO: suplencia
            ]
            
            # Verificar si el archivo existe y leer su contenido
            try:
                with sftp.file(remote_file_path, 'r') as archivo_remoto:
                    contenido_existente = archivo_remoto.read().decode('utf-8')
            except:
                contenido_existente = ""
            
            # Agregar el nuevo registro
            output = io.StringIO()
            writer = csv.writer(output)
            if contenido_existente.strip():
                # Si el archivo ya tiene contenido, agregar nueva línea
                output.write(contenido_existente.strip() + '\n')
            writer.writerow(fila_csv)
            
            # Escribir el contenido actualizado al archivo remoto
            with sftp.file(remote_file_path, 'w') as archivo_remoto:
                archivo_remoto.write(output.getvalue())
            
            sftp.close()
            ssh.close()
            
            st.success("✅ Registro agregado exitosamente al archivo remoto.")
            return True
            
        except Exception as e:
            st.error(f"❌ Error al escribir en el archivo remoto: {e}")
            try:
                sftp.close()
            except:
                pass
            try:
                ssh.close()
            except:
                pass
            return False

    def buscar_usuario_por_password(self, password):
        """Buscar usuario por contraseña en archivo remoto"""
        ssh = self.conectar_ssh()
        if not ssh:
            return None, None
        
        try:
            sftp = ssh.open_sftp()
            remote_file_path = f"{self.remote_config['remote_dir']}/{self.remote_config['file_creacion_enfermeras2']}"
            
            # Verificar si el archivo existe
            try:
                with sftp.file(remote_file_path, 'r') as archivo_remoto:
                    contenido = archivo_remoto.read().decode('utf-8')
            except:
                contenido = ""
            
            sftp.close()
            ssh.close()
            
            if not contenido.strip():
                return None, None
            
            # Leer el archivo CSV y buscar la contraseña
            try:
                df = pd.read_csv(io.StringIO(contenido))
                
                # Buscar la contraseña en la columna 5 (password)
                if not df.empty and len(df.columns) > 5:
                    for index, row in df.iterrows():
                        if str(row[5]) == password:  # Columna de password
                            # Crear objeto usuario con los datos del archivo remoto
                            usuario = {
                                'numero_economico': str(row[0]),
                                'nombre_completo': str(row[2]),  # nombre_completo
                                'puesto': str(row[1]),           # puesto
                                'servicio': str(row[3]),         # servicio
                                'turno_laboral': str(row[4]),    # turno
                                'password': str(row[5]),         # password
                                'correo_electronico': str(row[6]) if len(df.columns) > 6 else "",  # email
                                'suplencia': str(row[7]) if len(df.columns) > 7 else "NO"  # suplencia
                            }
                            return usuario['numero_economico'], usuario
                
                return None, None
                
            except Exception as e:
                return None, None
                
        except Exception as e:
            return None, None

    def obtener_registro_anterior_asistencia(self, numero_economico):
        """Obtiene el registro anterior del usuario en el archivo de asistencia"""
        ssh = self.conectar_ssh()
        if not ssh:
            return None
        
        try:
            sftp = ssh.open_sftp()
            remote_file_path = f"{self.remote_config['remote_dir']}/{self.remote_config['file_asistencia_enfermeras2']}"
            
            # Verificar si el archivo existe
            try:
                with sftp.file(remote_file_path, 'r') as archivo_remoto:
                    contenido = archivo_remoto.read().decode('utf-8')
            except:
                contenido = ""
            
            sftp.close()
            ssh.close()
            
            if not contenido.strip():
                return None
            
            # Leer el archivo CSV
            df = pd.read_csv(io.StringIO(contenido))
            
            # Buscar registros del usuario
            registros_usuario = df[df['numero_economico'] == numero_economico]
            
            if registros_usuario.empty:
                return None
            
            # Devolver el registro más reciente
            return registros_usuario.iloc[-1].to_dict()
            
        except Exception as e:
            return None

    def mover_registros_anteriores_historico(self, numero_economico):
        """Mueve TODOS los registros anteriores del usuario al histórico"""
        ssh = self.conectar_ssh()
        if not ssh:
            st.error("❌ No se pudo conectar al servidor para mover registros al histórico")
            return False
        
        try:
            sftp = ssh.open_sftp()
            asistencia_path = f"{self.remote_config['remote_dir']}/{self.remote_config['file_asistencia_enfermeras2']}"
            historico_path = f"{self.remote_config['remote_dir']}/{self.remote_config['file_historico_enfermeras2']}"
            
            # Leer archivo de asistencia
            try:
                with sftp.file(asistencia_path, 'r') as archivo:
                    contenido_asistencia = archivo.read().decode('utf-8')
            except FileNotFoundError:
                # Si el archivo no existe, no hay nada que mover
                sftp.close()
                ssh.close()
                return True
            except Exception as e:
                st.error(f"❌ Error al leer archivo de asistencia: {e}")
                sftp.close()
                ssh.close()
                return False
            
            # Si no hay contenido en asistencia, no hay nada que mover
            if not contenido_asistencia.strip():
                sftp.close()
                ssh.close()
                return True
            
            try:
                # Procesar archivo de asistencia
                df_asistencia = pd.read_csv(io.StringIO(contenido_asistencia))
                
                # CORRECCIÓN: Convertir numero_economico a string para comparación consistente
                numero_economico_str = str(numero_economico)
                
                # CORRECCIÓN: Convertir la columna numero_economico a string para comparación
                if 'numero_economico' in df_asistencia.columns:
                    df_asistencia['numero_economico'] = df_asistencia['numero_economico'].astype(str)
                
                # Buscar TODOS los registros del usuario (comparación como strings)
                registros_usuario = df_asistencia[df_asistencia['numero_economico'] == numero_economico_str]
                
                if registros_usuario.empty:
                    sftp.close()
                    ssh.close()
                    return True
                
                st.info(f"📋 Se encontraron {len(registros_usuario)} registros anteriores para el usuario {numero_economico_str}")
                
                # Leer archivo histórico
                try:
                    with sftp.file(historico_path, 'r') as archivo:
                        contenido_historico = archivo.read().decode('utf-8')
                except FileNotFoundError:
                    contenido_historico = ""
                except Exception as e:
                    st.error(f"❌ Error al leer archivo histórico: {e}")
                    sftp.close()
                    ssh.close()
                    return False
                
                # Procesar archivo histórico
                if contenido_historico.strip():
                    df_historico = pd.read_csv(io.StringIO(contenido_historico))
                    # CORRECCIÓN: Convertir también en el histórico para consistencia
                    if 'numero_economico' in df_historico.columns:
                        df_historico['numero_economico'] = df_historico['numero_economico'].astype(str)
                else:
                    # Si no existe histórico, crear uno con las mismas columnas que asistencia
                    df_historico = pd.DataFrame(columns=df_asistencia.columns)
                
                # CORRECCIÓN CRÍTICA: Asegurar que los registros a mover tengan la misma estructura
                columnas_comunes = [col for col in registros_usuario.columns if col in df_historico.columns]
                if not columnas_comunes:
                    # Si no hay columnas comunes, usar las del histórico
                    columnas_comunes = df_historico.columns.tolist()
                
                registros_a_mover = registros_usuario[columnas_comunes].copy()
                
                # Agregar TODOS los registros del usuario al histórico
                df_historico = pd.concat([df_historico, registros_a_mover], ignore_index=True)
                
                # Eliminar TODOS los registros del usuario del archivo de asistencia
                df_asistencia = df_asistencia[df_asistencia['numero_economico'] != numero_economico_str]
                
                # Guardar archivo de asistencia actualizado
                with sftp.file(asistencia_path, 'w') as archivo:
                    archivo.write(df_asistencia.to_csv(index=False))
                
                # Guardar archivo histórico actualizado
                with sftp.file(historico_path, 'w') as archivo:
                    archivo.write(df_historico.to_csv(index=False))
                
                sftp.close()
                ssh.close()
                
                st.success(f"✅ Se movieron {len(registros_usuario)} registros anteriores al histórico")
                return True
                
            except Exception as e:
                st.error(f"❌ Error al procesar datos CSV: {e}")
                sftp.close()
                ssh.close()
                return False
            
        except Exception as e:
            st.error(f"❌ Error general al mover registros al histórico: {e}")
            try:
                sftp.close()
            except:
                pass
            try:
                ssh.close()
            except:
                pass
            return False

    def agregar_asistencia_remota(self, datos_asistencia):
        """Agrega un registro de asistencia al archivo remoto con gestión de histórico"""
        ssh = self.conectar_ssh()
        if not ssh:
            st.error("❌ No se pudo conectar al servidor remoto.")
            return False
        
        try:
            sftp = ssh.open_sftp()
            asistencia_path = f"{self.remote_config['remote_dir']}/{self.remote_config['file_asistencia_enfermeras2']}"
            
            # PRIMERO: Mover TODOS los registros anteriores del usuario al histórico
            numero_economico_actual = datos_asistencia['numero_economico']
            
            with st.spinner("🔄 Moviendo registros anteriores al histórico..."):
                exito_mover = self.mover_registros_anteriores_historico(numero_economico_actual)
                
                if not exito_mover:
                    st.warning("⚠️ No se pudieron mover los registros anteriores al histórico, pero se procederá con el registro actual")
            
            # SEGUNDO: Leer archivo de asistencia actualizado (sin los registros del usuario)
            try:
                with sftp.file(asistencia_path, 'r') as archivo:
                    contenido_asistencia = archivo.read().decode('utf-8')
            except FileNotFoundError:
                contenido_asistencia = ""
            except Exception as e:
                st.error(f"❌ Error al leer archivo de asistencia: {e}")
                sftp.close()
                ssh.close()
                return False
            
            # TERCERO: Agregar el nuevo registro al archivo de asistencia
            if contenido_asistencia.strip():
                try:
                    df_asistencia = pd.read_csv(io.StringIO(contenido_asistencia))
                    # CORRECCIÓN: Convertir también aquí para consistencia
                    if 'numero_economico' in df_asistencia.columns:
                        df_asistencia['numero_economico'] = df_asistencia['numero_economico'].astype(str)
                except Exception as e:
                    st.error(f"❌ Error al procesar archivo de asistencia: {e}")
                    sftp.close()
                    ssh.close()
                    return False
            else:
                df_asistencia = pd.DataFrame()
            
            # CORRECCIÓN: Asegurar que el nuevo registro también tenga el tipo correcto
            datos_asistencia['numero_economico'] = str(datos_asistencia['numero_economico'])
            
            # Si el DataFrame de asistencia está vacío, establecer las columnas
            if df_asistencia.empty:
                df_asistencia = pd.DataFrame(columns=datos_asistencia.keys())
            
            # Agregar el nuevo registro al archivo de asistencia
            nuevo_registro_df = pd.DataFrame([datos_asistencia])
            df_asistencia = pd.concat([df_asistencia, nuevo_registro_df], ignore_index=True)
            
            # Guardar archivo de asistencia actualizado
            with sftp.file(asistencia_path, 'w') as archivo:
                archivo.write(df_asistencia.to_csv(index=False))
            
            sftp.close()
            ssh.close()
            
            return True
            
        except Exception as e:
            st.error(f"❌ Error al escribir la asistencia en el archivo remoto: {e}")
            try:
                sftp.close()
            except:
                pass
            try:
                ssh.close()
            except:
                pass
            return False

    def determinar_fecha_turno(self, turno_laboral, hora_actual_str):
        """CORREGIDO: Determina la fecha correcta para turnos que cruzan medianoche usando hora de México"""
        try:
            # Si no es turno nocturno, usar fecha actual de México
            if turno_laboral not in self.TURNOS_NOCTURNOS:
                return self.obtener_fecha_hora_actual_mexico().strftime("%Y-%m-%d")
            
            # Parsear la hora actual
            hora_actual = datetime.datetime.strptime(hora_actual_str, "%H:%M").time()
            
            # Si es turno nocturno y la hora es antes de las 8:00 AM, usar el día anterior
            if hora_actual < datetime.time(8, 0):  # Antes de las 8:00 AM
                fecha_correcta = (self.obtener_fecha_hora_actual_mexico() - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
                return fecha_correcta
            
            # Para el resto del día, usar fecha actual de México
            return self.obtener_fecha_hora_actual_mexico().strftime("%Y-%m-%d")
            
        except Exception:
            # En caso de error, devolver fecha actual de México
            return self.obtener_fecha_hora_actual_mexico().strftime("%Y-%m-%d")

    def validar_password(self, password):
        """Valida que la contraseña cumpla con los requisitos de seguridad"""
        errores = []
        
        # Longitud mínima
        if len(password) < 8:
            errores.append("La contraseña debe tener al menos 8 caracteres")
        
        # Al menos una mayúscula
        if not re.search(r'[A-Z]', password):
            errores.append("La contraseña debe contener al menos una letra mayúscula (A-Z)")
        
        # Al menos una minúscula
        if not re.search(r'[a-z]', password):
            errores.append("La contraseña debe contener al menos una letra minúscula (a-z)")
        
        # Al menos un número
        if not re.search(r'\d', password):
            errores.append("La contraseña debe contener al menos un número (0-9)")
        
        # Solo caracteres especiales permitidos: $#&
        caracteres_permitidos = r'^[A-Za-z0-9$#&]+$'
        if not re.match(caracteres_permitidos, password):
            errores.append("La contraseña solo puede contener letras, números y los caracteres especiales: $ # &")
        
        # Verificar caracteres NO permitidos específicamente
        caracteres_no_permitidos = r'[.,\-_]'
        if re.search(caracteres_no_permitidos, password):
            errores.append("La contraseña NO puede contener: comas (,), puntos (.), guiones (-) o guiones bajos (_)")
        
        if errores:
            return False, errores
        else:
            return True, "Contraseña válida"

    def validar_correo(self, correo):
        """Valida que el correo tenga un formato válido"""
        if not correo:
            return True, ""  # Correo opcional, vacío es válido
        
        patron = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(patron, correo):
            return True, "Correo válido"
        else:
            return False, "Formato de correo electrónico inválido"

    def mostrar_validacion_password_en_tiempo_real(self, password):
        """Muestra la validación de la contraseña en tiempo real"""
        if not password:
            return
        
        # Validar longitud
        longitud_ok = len(password) >= 8
        longitud_icono = "✅" if longitud_ok else "❌"
        longitud_color = "password-success" if longitud_ok else "password-error"
        
        # Validar mayúscula
        mayuscula_ok = bool(re.search(r'[A-Z]', password))
        mayuscula_icono = "✅" if mayuscula_ok else "❌"
        mayuscula_color = "password-success" if mayuscula_ok else "password-error"
        
        # Validar minúscula
        minuscula_ok = bool(re.search(r'[a-z]', password))
        minuscula_icono = "✅" if minuscula_ok else "❌"
        minuscula_color = "password-success" if minuscula_ok else "password-error"
        
        # Validar número
        numero_ok = bool(re.search(r'\d', password))
        numero_icono = "✅" if numero_ok else "❌"
        numero_color = "password-success" if numero_ok else "password-error"
        
        # Validar caracteres especiales permitidos
        caracteres_ok = bool(re.match(r'^[A-Za-z0-9$#&]+$', password))
        caracteres_icono = "✅" if caracteres_ok else "❌"
        caracteres_color = "password-success" if caracteres_ok else "password-error"
        
        # Validar caracteres NO permitidos
        caracteres_no_permitidos = not bool(re.search(r'[.,\-_]', password))
        caracteres_no_icono = "✅" if caracteres_no_permitidos else "❌"
        caracteres_no_color = "password-success" if caracteres_no_permitidos else "password-error"
        
        st.markdown(f"""
        <div style="font-size: 0.8rem; margin-top: 0.5rem;">
            <div class="{longitud_color}">{longitud_icono} Mínimo 8 caracteres</div>
            <div class="{mayuscula_color}">{mayuscula_icono} Al menos una mayúscula (A-Z)</div>
            <div class="{minuscula_color}">{minuscula_icono} Al menos una minúscula (a-z)</div>
            <div class="{numero_color}">{numero_icono} Al menos un número (0-9)</div>
            <div class="{caracteres_color}">{caracteres_icono} Solo caracteres especiales permitidos: $ # &</div>
            <div class="{caracteres_no_color}">{caracteres_no_icono} NO usar: , . - _</div>
        </div>
        """, unsafe_allow_html=True)

    def mostrar_seleccion_modo(self):
        """Muestra la selección de modo (Login o Registro)"""
        st.title("🏥 Sistema de Registro de Enfermería")
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🔐 Inicio de Sesión")
            st.markdown("""
            **Para personal registrado:**
            - Ingrese su contraseña única
            - Registre su hora de entrada
            - Acceda a su historial
            - 📧 Reciba confirmación por correo
            """)
            if st.button("🚀 Ir a Inicio de Sesión", use_container_width=True):
                st.session_state.modo = "login"
                st.rerun()
        
        with col2:
            st.subheader("📝 Registro Nuevo")
            st.markdown("""
            **Para nuevo personal:**
            - Complete el formulario de registro
            - Elija puesto y servicio
            - Cree su contraseña única
            - 📧 Agregue su correo electrónico (opcional)
            - 📋 Indique si es suplencia
            """)
            if st.button("📋 Ir a Registro", use_container_width=True):
                st.session_state.modo = "registro"
                st.rerun()

    def registrar_usuario(self):
        """Interfaz de registro de usuario - SOLO ARCHIVOS REMOTOS"""
        # Botón para volver al menú principal
        if st.button("← Volver al Menú Principal"):
            st.session_state.modo = None
            st.rerun()
        
        st.title("📝 Registro de Nuevo Usuario")
        st.markdown("Complete el siguiente formulario para registrarse en el sistema.")
        st.markdown("---")
        
        # Estado para controlar si se mostró el resultado del registro
        if 'registro_exitoso' not in st.session_state:
            st.session_state.registro_exitoso = False
        if 'datos_registro' not in st.session_state:
            st.session_state.datos_registro = None
        
        if st.session_state.registro_exitoso and st.session_state.datos_registro:
            # Mostrar resultados del registro exitoso
            datos = st.session_state.datos_registro
            st.success("¡Registro exitoso! ✅")
            st.balloons()
            
            # Mostrar resumen del registro CON LA CONTRASEÑA
            st.subheader("📄 Resumen del Registro")
            
            col_info1, col_info2 = st.columns(2)
            with col_info1:
                st.write(f"**Número económico:** `{datos['numero_economico']}`")
                st.write(f"**Nombre:** {datos['nombre_completo']}")
                st.write(f"**Puesto:** {datos['puesto']}")
                st.write(f"**Contraseña:** `{datos['password']}`")
                if datos.get('correo_electronico'):
                    st.write(f"**Correo electrónico:** {datos['correo_electronico']}")
            
            with col_info2:
                st.write(f"**Servicio:** {datos['servicio']}")
                st.write(f"**Turno:** {datos['turno_laboral']}")
                st.write(f"**Suplencia:** {datos.get('suplencia', 'NO')}")
                st.write(f"**Fecha de registro:** {datos['fecha_registro']}")
            
            st.success("✅ **Registro guardado en servidor remoto**")
            
            # Información importante para el usuario
            st.info("""
            🔒 **Información importante:**
            - **Guarde su número económico y contraseña** para futuros accesos
            - Use su **contraseña única** para iniciar sesión en el sistema
            - Su horario de entrada se registrará automáticamente al iniciar sesión
            - **La contraseña se muestra arriba para que la anote**
            - Si agregó su correo, recibirá confirmaciones de sus registros
            """)
            
            # Advertencia sobre la contraseña
            st.warning("""
            ⚠️ **ADVERTENCIA: ANOTE SU CONTRASEÑA**
            - Esta es la única vez que podrá ver su contraseña
            - No podrá recuperarla si la olvida
            - Guárdela en un lugar seguro
            - Su contraseña es **ÚNICA** en el sistema
            """)
            
            # Botón para ir a login después del registro
            st.markdown("---")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔐 Ir a Inicio de Sesión", use_container_width=True):
                    st.session_state.registro_exitoso = False
                    st.session_state.datos_registro = None
                    st.session_state.modo = "login"
                    st.rerun()
            with col2:
                if st.button("📝 Registrar Otro Usuario", use_container_width=True):
                    st.session_state.registro_exitoso = False
                    st.session_state.datos_registro = None
                    st.rerun()
        
        else:
            # Inicializar session state para mantener los valores de los campos
            if 'form_data' not in st.session_state:
                st.session_state.form_data = {
                    'numero_economico': '',
                    'nombre_completo': '',
                    'puesto': '',
                    'servicio': '',
                    'turno_laboral': '',
                    'password': '',
                    'confirmar_password': '',
                    'correo_electronico': '',
                    'suplencia': 'NO'
                }
            
            # Mostrar formulario de registro
            with st.form("formulario_registro", clear_on_submit=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    numero_economico = st.text_input(
                        "Número económico*", 
                        value=st.session_state.form_data['numero_economico'],
                        placeholder="Ingrese su número económico", 
                        help="Este número debe ser único", 
                        max_chars=20,
                        key="numero_economico_input"
                    )
                    
                    nombre_completo = st.text_input(
                        "Nombre completo*", 
                        value=st.session_state.form_data['nombre_completo'],
                        placeholder="Nombre(s) Apellidos", 
                        help="Ejemplo: María Guadalupe Hernández García", 
                        max_chars=100,
                        key="nombre_completo_input"
                    )
                    
                    # Selector de puesto
                    puesto_index = 0
                    if st.session_state.form_data['puesto']:
                        try:
                            puesto_index = self.PUESTOS.index(st.session_state.form_data['puesto']) + 1
                        except ValueError:
                            puesto_index = 0
                    
                    puesto = st.selectbox(
                        "Puesto*", 
                        [""] + self.PUESTOS, 
                        index=puesto_index,
                        help="Seleccione su puesto",
                        key="puesto_select"
                    )
                    
                    # NUEVO CAMPO: Suplencia (SI/NO)
                    suplencia_options = ["NO", "SI"]
                    suplencia_index = suplencia_options.index(st.session_state.form_data['suplencia'])
                    suplencia = st.selectbox(
                        "¿Es suplencia?*",
                        options=suplencia_options,
                        index=suplencia_index,
                        help="Seleccione SI si es una suplencia, NO si es personal regular",
                        key="suplencia_select"
                    )
                    
                with col2:
                    # Selector de servicio
                    servicio_index = 0
                    if st.session_state.form_data['servicio']:
                        try:
                            servicio_index = self.SERVICIOS.index(st.session_state.form_data['servicio']) + 1
                        except ValueError:
                            servicio_index = 0
                    
                    servicio = st.selectbox(
                        "Servicio*", 
                        [""] + self.SERVICIOS, 
                        index=servicio_index,
                        help="Seleccione su servicio",
                        key="servicio_select"
                    )
                    
                    # Selector de turno
                    turno_index = 0
                    if st.session_state.form_data['turno_laboral']:
                        try:
                            turno_index = self.TURNOS.index(st.session_state.form_data['turno_laboral']) + 1
                        except ValueError:
                            turno_index = 0
                    
                    turno_laboral = st.selectbox(
                        "Turno laboral*", 
                        [""] + self.TURNOS, 
                        index=turno_index,
                        help="Seleccione su turno laboral",
                        key="turno_select"
                    )
                    
                    # NUEVO CAMPO: Correo electrónico
                    correo_electronico = st.text_input(
                        "Correo electrónico (Opcional)",
                        value=st.session_state.form_data['correo_electronico'],
                        placeholder="ejemplo@unam.mx",
                        help="Agregue su correo para recibir confirmaciones de sus registros",
                        key="correo_input"
                    )
                    
                    # Validación de correo en tiempo real
                    if correo_electronico:
                        correo_valido, mensaje_correo = self.validar_correo(correo_electronico)
                        if not correo_valido:
                            st.error(f"❌ {mensaje_correo}")
                        else:
                            st.success(f"✅ {mensaje_correo}")
                
                st.markdown("---")
                st.subheader("🔒 Configuración de Contraseña")
                
                # MOSTRAR PASSWORD EN TEXTO PLANO PARA QUE EL USUARIO VEA LOS ERRORES
                mostrar_password = st.checkbox("👁️ Mostrar contraseña", key="mostrar_password")
                
                if mostrar_password:
                    password = st.text_input(
                        "Contraseña*", 
                        value=st.session_state.form_data['password'],
                        placeholder="Cree una contraseña única", 
                        help="La contraseña debe cumplir con los requisitos de seguridad", 
                        max_chars=50, 
                        key="password_input_visible"
                    )
                    confirmar_password = st.text_input(
                        "Confirmar contraseña*", 
                        value=st.session_state.form_data['confirmar_password'],
                        placeholder="Repita la contraseña", 
                        max_chars=50, 
                        key="confirm_password_input_visible"
                    )
                else:
                    password = st.text_input(
                        "Contraseña*", 
                        value=st.session_state.form_data['password'],
                        type="password",
                        placeholder="Cree una contraseña única", 
                        help="La contraseña debe cumplir con los requisitos de seguridad", 
                        max_chars=50, 
                        key="password_input_hidden"
                    )
                    confirmar_password = st.text_input(
                        "Confirmar contraseña*", 
                        value=st.session_state.form_data['confirmar_password'],
                        type="password",
                        placeholder="Repita la contraseña", 
                        max_chars=50, 
                        key="confirm_password_input_hidden"
                    )
                
                # Mostrar validación en tiempo real
                if password:
                    self.mostrar_validacion_password_en_tiempo_real(password)
                
                # Mostrar requisitos de contraseña
                st.markdown("""
                <div class="password-requirements">
                <strong>🔒 Requisitos de la contraseña:</strong>
                <ul>
                    <li>Mínimo 8 caracteres</li>
                    <li>Al menos una letra mayúscula (A-Z)</li>
                    <li>Al menos una letra minúscula (a-z)</li>
                    <li>Al menos un número (0-9)</li>
                    <li><strong>Solo caracteres especiales permitidos: $ # &</strong></li>
                    <li><strong>NO se permiten: , . - _</strong></li>
                    <li><strong>La contraseña debe ser ÚNICA en todo el sistema</strong></li>
                </ul>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("**Campos obligatorios***")
                
                # Botón de envío
                submitted = st.form_submit_button("📋 Registrar Usuario", use_container_width=True)
                
                if submitted:
                    # Actualizar session state con los valores actuales
                    st.session_state.form_data = {
                        'numero_economico': numero_economico,
                        'nombre_completo': nombre_completo,
                        'puesto': puesto,
                        'servicio': servicio,
                        'turno_laboral': turno_laboral,
                        'password': password,
                        'confirmar_password': confirmar_password,
                        'correo_electronico': correo_electronico,
                        'suplencia': suplencia
                    }
                    
                    # Validaciones
                    errores = []
                    
                    # VERIFICACIÓN DEL NÚMERO ECONÓMICO EN ARCHIVO REMOTO
                    if not numero_economico:
                        errores.append("El número económico es obligatorio.")
                    else:
                        with st.spinner("🔍 Verificando número económico..."):
                            numero_valido = self.validar_numero_economico(numero_economico)
                        if not numero_valido:
                            errores.append("Este número económico ya está registrado en el sistema. Intente con otro.")
                    
                    if not nombre_completo:
                        errores.append("El nombre completo es obligatorio.")
                    elif len(nombre_completo.strip().split()) < 2:
                        errores.append("Ingrese nombre(s) y apellido(s) completos.")
                    
                    if not puesto:
                        errores.append("Debe seleccionar un puesto.")
                    
                    if not servicio:
                        errores.append("Debe seleccionar un servicio.")
                    
                    if not turno_laboral:
                        errores.append("Debe seleccionar un turno laboral.")
                    
                    if not suplencia:
                        errores.append("Debe indicar si es suplencia o no.")
                    
                    if not password:
                        errores.append("La contraseña es obligatoria.")
                    else:
                        # Validar formato de contraseña
                        password_valida, mensajes_error = self.validar_password(password)
                        if not password_valida:
                            for error in mensajes_error:
                                errores.append(error)
                        elif password != confirmar_password:
                            errores.append("Las contraseñas no coinciden.")
                        else:
                            # NUEVA VERIFICACIÓN: Verificar que la contraseña sea única en el archivo remoto
                            with st.spinner("🔍 Verificando contraseña en sistema remoto..."):
                                password_existe_remoto, mensaje_remoto = self.verificar_password_remoto(password)
                            
                            if password_existe_remoto:
                                errores.append(mensaje_remoto)
                    
                    # Validar correo si se proporcionó
                    if correo_electronico:
                        correo_valido, mensaje_correo = self.validar_correo(correo_electronico)
                        if not correo_valido:
                            errores.append(mensaje_correo)
                    
                    if errores:
                        # Mostrar errores específicos
                        st.error("**Se encontraron los siguientes errores:**")
                        for error in errores:
                            st.error(f"❌ {error}")
                        
                        # Sugerir mostrar la contraseña si hay errores en ella
                        if any('contraseña' in error.lower() for error in errores):
                            st.warning("💡 **Sugerencia:** Active 'Mostrar contraseña' para verificar los caracteres ingresados.")
                        
                        return
                    
                    # Si no hay errores, proceder con el registro
                    # Preparar datos para el archivo remoto CON LOS NUEVOS CAMPOS
                    datos_remoto = {
                        'numero_economico': numero_economico,
                        'puesto': puesto,
                        'nombre_completo': nombre_completo,
                        'servicio': servicio,
                        'turno_laboral': turno_laboral,
                        'password': password,
                        'correo_electronico': correo_electronico,
                        'suplencia': suplencia
                    }
                    
                    # Agregar registro al archivo remoto
                    with st.spinner("Guardando registro en servidor remoto..."):
                        exito_remoto = self.agregar_registro_remoto(datos_remoto)
                    
                    if not exito_remoto:
                        st.error("❌ Error al guardar en servidor remoto. Intente nuevamente.")
                        return
                    
                    # Limpiar el formulario después de registro exitoso
                    st.session_state.form_data = {
                        'numero_economico': '',
                        'nombre_completo': '',
                        'puesto': '',
                        'servicio': '',
                        'turno_laboral': '',
                        'password': '',
                        'confirmar_password': '',
                        'correo_electronico': '',
                        'suplencia': 'NO'
                    }
                    
                    # Guardar datos para mostrar en la siguiente ejecución
                    st.session_state.registro_exitoso = True
                    st.session_state.datos_registro = {
                        'numero_economico': numero_economico,
                        'nombre_completo': nombre_completo,
                        'puesto': puesto,
                        'servicio': servicio,
                        'turno_laboral': turno_laboral,
                        'password': password,
                        'correo_electronico': correo_electronico,
                        'suplencia': suplencia,
                        'fecha_registro': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    st.rerun()

    def mostrar_login(self):
        """Pantalla de inicio de sesión - SOLO ARCHIVOS REMOTOS"""
        # Botón para volver al menú principal
        if st.button("← Volver al Menú Principal"):
            st.session_state.modo = None
            st.session_state.usuario_autenticado = None
            st.rerun()
        
        st.title("🔐 Inicio de Sesión")
        st.markdown("Ingrese su **contraseña única** para acceder al sistema de asistencia.")
        st.markdown("---")
        
        with st.form("formulario_login"):
            password = st.text_input(
                "Contraseña única", 
                type="password", 
                placeholder="Ingrese su contraseña única",
                help="Ingrese la contraseña única que creó durante el registro",
                max_chars=50
            )
            
            submitted = st.form_submit_button("🚀 Iniciar Sesión", use_container_width=True)
            
            if submitted:
                if not password:
                    st.error("Por favor, ingrese su contraseña.")
                    return
                
                # Buscar usuario por contraseña EN ARCHIVO REMOTO
                with st.spinner("🔍 Verificando credenciales en servidor..."):
                    numero_economico, usuario = self.buscar_usuario_por_password(password)
                
                if not usuario:
                    st.error("❌ Contraseña incorrecta o no encontrada.")
                    return
                
                # Autenticación exitosa
                st.session_state.usuario_autenticado = usuario
                st.session_state.numero_economico = numero_economico
                st.session_state.modo = "asistencia"
                st.success("✅ Autenticación exitosa!")
                time.sleep(1)
                st.rerun()
        
        # Información para el usuario
        st.info("""
        💡 **Recordatorio:**
        - Solo necesita su **contraseña única** para acceder
        - El sistema verifica directamente en el servidor remoto
        - Si olvidó su contraseña, contacte al administrador
        """)
        
        # Botón de cerrar (fuera del formulario)
        st.markdown("---")
        if st.button("🚪 Salir del Sistema", use_container_width=True):
            st.session_state.modo = None
            st.rerun()

    def mostrar_sistema_asistencia(self):
        """Mostrar el sistema de asistencia después del login exitoso"""
        usuario = st.session_state.usuario_autenticado
        numero_economico = st.session_state.numero_economico
        
        st.markdown('<h1 class="header-text">⏰ Sistema de Asistencia</h1>', unsafe_allow_html=True)
        st.markdown("---")
        
        # CORREGIDO: Siempre mostrar solo ENTRADA, nunca SALIDA
        tipo_registro = "ENTRADA"
        
        # Mostrar información del empleado
        st.markdown(f"""
        <div class="info-box">
        <h3>👤 Información Personal</h3>
        <p><strong>Nombre completo:</strong> {usuario['nombre_completo']}</p>
        <p><strong>Puesto:</strong> {usuario['puesto']}</p>
        <p><strong>Servicio:</strong> {usuario['servicio']}</p>
        <p><strong>Turno asignado:</strong> {usuario['turno_laboral']}</p>
        <p><strong>Número económico:</strong> {numero_economico}</p>
        <p><strong>Suplencia:</strong> {usuario.get('suplencia', 'NO')}</p>
        <p><strong>Tipo de registro:</strong> <span style='color: green; font-weight: bold;'>ENTRADA</span></p>
        </div>
        """, unsafe_allow_html=True)
        
        # Verificar si existe un registro anterior para este usuario
        registro_anterior = self.obtener_registro_anterior_asistencia(numero_economico)
        
        if registro_anterior:
            st.info(f"📋 **Registro anterior encontrado:** {registro_anterior.get('fecha_turno', 'N/A')} - {registro_anterior.get('incidencias', 'N/A')} - Suplencia: {registro_anterior.get('suplencia', 'N/A')}")
        
        # Opción para registrar incidencia en lugar de asistencia normal
        st.markdown("---")
        st.subheader("📋 Opciones de Registro")
        
        col1, col2 = st.columns(2)
        
        with col1:
            registrar_asistencia_normal = st.button(
                "✅ Registrar Entrada Normal", 
                use_container_width=True,
                type="primary",
                help="Registrar entrada sin incidencias"
            )
        
        with col2:
            # CORREGIDO: Ahora el botón de incidencia cambia el estado para mostrar el formulario
            if st.button("🚨 Registrar Incidencia", use_container_width=True):
                st.session_state.mostrar_formulario_incidencia = True
                st.rerun()
        
        # Procesar registro de asistencia normal
        if registrar_asistencia_normal:
            with st.spinner("Procesando registro de asistencia..."):
                time.sleep(1.5)
                
                # CORREGIDO: Obtener fecha y hora actual DE CIUDAD DE MÉXICO
                ahora_mexico = self.obtener_fecha_hora_actual_mexico()
                fecha_completa = ahora_mexico.strftime("%Y-%m-%d %H:%M")
                hora_actual = ahora_mexico.strftime("%H:%M")
                
                # Determinar fecha de turno
                fecha_turno = self.determinar_fecha_turno(usuario['turno_laboral'], hora_actual)
                
                # Preparar datos para archivo remoto CON EL NUEVO CAMPO SUPLENCIA
                datos_asistencia = {
                    'fecha': fecha_completa,
                    'fecha_turno': fecha_turno,
                    'numero_economico': numero_economico,
                    'puesto': usuario['puesto'],
                    'nombre_completo': usuario['nombre_completo'],
                    'servicio': usuario['servicio'],
                    'turno_laboral': usuario['turno_laboral'],
                    'hora_entrada': hora_actual,
                    'incidencias': "NO",
                    'suplencia': usuario.get('suplencia', 'NO')
                }
                
                # Registrar en archivo remoto
                exito_remoto = self.agregar_asistencia_remota(datos_asistencia)
                
                # Registrar también en el sistema local de asistencia
                exito_local, resultado = self.sistema_asistencia.registrar_asistencia(
                    tipo_registro, usuario, usuario['password']
                )
                
                if exito_local and exito_remoto:
                    st.balloons()
                    st.markdown(f"""
                    <div class="success-box">
                    <h3>🎉 ¡Registro Exitoso!</h3>
                    <p><strong>Nombre:</strong> {resultado['NOMBRE_COMPLETO']}</p>
                    <p><strong>Puesto:</strong> {resultado['PUESTO']}</p>
                    <p><strong>Servicio:</strong> {usuario['servicio']}</p>
                    <p><strong>Turno:</strong> {resultado['TURNO']}</p>
                    <p><strong>Suplencia:</strong> {usuario.get('suplencia', 'NO')}</p>
                    <p><strong>Tipo de registro:</strong> {resultado['TIPO_REGISTRO']}</p>
                    <p><strong>Fecha:</strong> {resultado['FECHA']}</p>
                    <p><strong>Hora exacta:</strong> {resultado['HORA']}</p>
                    <p><strong>Método:</strong> 📱 Sistema Web</p>
                    <p><strong>Incidencia:</strong> NO (Asistencia normal)</p>
                    <p><strong>Estado archivo remoto:</strong> ✅ Solo registro más reciente conservado</p>
                    <p><strong>Registros anteriores:</strong> ✅ Movidos al histórico</p>
                    <p><strong>Zona horaria:</strong> Ciudad de México</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # ENVIAR CORREO DE CONFIRMACIÓN si el usuario tiene correo
                    if usuario.get('correo_electronico'):
                        with st.spinner("📧 Enviando correo de confirmación..."):
                            datos_correo = {
                                'nombre_completo': usuario['nombre_completo'],
                                'puesto': usuario['puesto'],
                                'servicio': usuario['servicio'],
                                'turno_laboral': usuario['turno_laboral'],
                                'fecha': ahora_mexico.strftime('%Y-%m-%d'),
                                'hora_registro': ahora_mexico.strftime('%H:%M:%S'),
                                'tipo_registro': tipo_registro,
                                'incidencia': 'NO',
                                'suplencia': usuario.get('suplencia', 'NO')
                            }
                            
                            exito_correo, mensaje_correo = self.sistema_correo.enviar_correo_confirmacion(
                                usuario['correo_electronico'],
                                datos_correo
                            )
                            
                            if exito_correo:
                                st.success(f"📧 {mensaje_correo}")
                            else:
                                st.warning(f"⚠️ {mensaje_correo}")
                        
                    # Recargar la página para actualizar el estado
                    st.rerun()
                else:
                    st.error(f"❌ Error al registrar: {resultado}")
        
        # CORREGIDO: Mostrar formulario de incidencia cuando se activa
        if st.session_state.get('mostrar_formulario_incidencia', False):
            st.markdown("---")
            st.subheader("🚨 Registro de Incidencia")
            
            # Sección de incidencia con estilo diferenciado
            st.markdown('<div class="incidencia-section">', unsafe_allow_html=True)
            
            # NUEVA TABLA DE INCIDENCIAS MEJORADA
            st.markdown("### 📋 Tipos de Incidencias Disponibles")
            
            # Crear opciones para el selectbox con código y descripción
            opciones_incidencias = ["NO - Sin incidencia"] + [
                f"{codigo} - {descripcion}" for codigo, descripcion in self.INCIDENCIAS.items()
            ]
            
            # Mostrar las incidencias en un selectbox organizado
            incidencia_seleccionada = st.selectbox(
                "Seleccione el tipo de incidencia:",
                options=opciones_incidencias,
                help="Seleccione el código de incidencia correspondiente",
                key="incidencia_select"
            )
            
            # Extraer el código de incidencia de la selección
            if incidencia_seleccionada != "NO - Sin incidencia":
                codigo_incidencia = incidencia_seleccionada.split(" - ")[0]
                descripcion_incidencia = self.INCIDENCIAS.get(codigo_incidencia, "")
                
                # Mostrar información de la incidencia seleccionada
                st.info(f"**Incidencia seleccionada:** {codigo_incidencia} - {descripcion_incidencia}")
            else:
                codigo_incidencia = "NO"
            
            # Calendario para seleccionar la fecha de la incidencia
            col_fecha, col_info = st.columns([1, 1])
            
            with col_fecha:
                fecha_incidencia = st.date_input(
                    "📅 Fecha de la incidencia",
                    value=datetime.date.today(),
                    help="Seleccione la fecha en que ocurre la incidencia"
                )
                
                # Convertir la fecha seleccionada al formato correcto
                fecha_incidencia_str = fecha_incidencia.strftime("%Y-%m-%d")
            
            with col_info:
                st.markdown("### ℹ️ Información")
                st.markdown("""
                **Nota importante:**
                - Seleccione la fecha correcta en que ocurre la incidencia
                - La incidencia reemplazará cualquier registro de asistencia para esa fecha
                - El sistema guardará automáticamente en el archivo remoto
                - Solo se conservará el registro más reciente en el archivo de asistencia
                - Los registros anteriores se moverán al histórico
                - El campo suplencia se mantendrá del registro original
                - **Zona horaria: Ciudad de México**
                """)
            
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Botones para confirmar o cancelar la incidencia
            col_confirmar, col_cancelar = st.columns(2)
            
            with col_confirmar:
                if st.button("📝 Confirmar Incidencia", type="primary", use_container_width=True):
                    if codigo_incidencia == "NO":
                        st.error("❌ Debe seleccionar un tipo de incidencia válido")
                        return
                        
                    with st.spinner("Procesando registro de incidencia..."):
                        time.sleep(1.5)
                        
                        # CORREGIDO: Obtener fecha y hora actual DE CIUDAD DE MÉXICO para el registro
                        ahora_mexico = self.obtener_fecha_hora_actual_mexico()
                        fecha_completa = ahora_mexico.strftime("%Y-%m-%d %H:%M")
                        hora_actual = ahora_mexico.strftime("%H:%M")
                        
                        # Usar la fecha seleccionada por el usuario como fecha_turno
                        fecha_turno = fecha_incidencia_str
                        
                        # CORRECCIÓN: Para incidencias, el campo hora_entrada debe tener "NO"
                        datos_asistencia = {
                            'fecha': fecha_completa,
                            'fecha_turno': fecha_turno,
                            'numero_economico': numero_economico,
                            'puesto': usuario['puesto'],
                            'nombre_completo': usuario['nombre_completo'],
                            'servicio': usuario['servicio'],
                            'turno_laboral': usuario['turno_laboral'],
                            'hora_entrada': "NO",  # CORREGIDO: Para incidencias debe ser "NO"
                            'incidencias': codigo_incidencia,
                            'suplencia': usuario.get('suplencia', 'NO')
                        }
                        
                        # Registrar en archivo remoto
                        exito_remoto = self.agregar_asistencia_remota(datos_asistencia)
                        
                        # Registrar también en el sistema local de asistencia
                        exito_local, resultado = self.sistema_asistencia.registrar_asistencia(
                            f"INCIDENCIA-{codigo_incidencia}", usuario, usuario['password']
                        )
                        
                        if exito_local and exito_remoto:
                            # ENVIAR CORREO DE CONFIRMACIÓN si el usuario tiene correo
                            if usuario.get('correo_electronico'):
                                with st.spinner("📧 Enviando correo de confirmación..."):
                                    datos_correo = {
                                        'nombre_completo': usuario['nombre_completo'],
                                        'puesto': usuario['puesto'],
                                        'servicio': usuario['servicio'],
                                        'turno_laboral': usuario['turno_laboral'],
                                        'fecha': ahora_mexico.strftime('%Y-%m-%d'),
                                        'hora_registro': ahora_mexico.strftime('%H:%M:%S'),
                                        'tipo_registro': f"INCIDENCIA-{codigo_incidencia}",
                                        'incidencia': f"{codigo_incidencia} - {descripcion_incidencia}",
                                        'suplencia': usuario.get('suplencia', 'NO')
                                    }
                                    
                                    exito_correo, mensaje_correo = self.sistema_correo.enviar_correo_confirmacion(
                                        usuario['correo_electronico'],
                                        datos_correo
                                    )
                            
                            st.markdown(f"""
                            <div class="success-box">
                            <h3>📋 ¡Incidencia Registrada Exitosamente!</h3>
                            <p><strong>Nombre:</strong> {resultado['NOMBRE_COMPLETO']}</p>
                            <p><strong>Puesto:</strong> {resultado['PUESTO']}</p>
                            <p><strong>Servicio:</strong> {usuario['servicio']}</p>
                            <p><strong>Turno:</strong> {resultado['TURNO']}</p>
                            <p><strong>Suplencia:</strong> {usuario.get('suplencia', 'NO')}</p>
                            <p><strong>Tipo de registro:</strong> INCIDENCIA</p>
                            <p><strong>Código de incidencia:</strong> {codigo_incidencia}</p>
                            <p><strong>Descripción:</strong> {descripcion_incidencia}</p>
                            <p><strong>Fecha de incidencia:</strong> {fecha_turno}</p>
                            <p><strong>Fecha de registro:</strong> {resultado['FECHA']}</p>
                            <p><strong>Hora exacta:</strong> {resultado['HORA']}</p>
                            <p><strong>Método:</strong> 📱 Sistema Web</p>
                            <p><strong>Estado:</strong> ✅ Guardado en archivo remoto</p>
                            <p><strong>Hora de entrada:</strong> NO (Incidencia registrada)</p>
                            <p><strong>Estado archivo remoto:</strong> ✅ Solo registro más reciente conservado</p>
                            <p><strong>Registros anteriores:</strong> ✅ Movidos al histórico</p>
                            <p><strong>Zona horaria:</strong> Ciudad de México</p>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            # Mostrar estado del correo si se envió
                            if usuario.get('correo_electronico'):
                                if exito_correo:
                                    st.success(f"📧 {mensaje_correo}")
                                else:
                                    st.warning(f"⚠️ {mensaje_correo}")
                            
                            # Limpiar el estado del formulario de incidencia
                            st.session_state.mostrar_formulario_incidencia = False
                            
                            # Recargar la página para actualizar el estado
                            st.rerun()
                        else:
                            st.error(f"❌ Error al registrar incidencia en el archivo remoto: {resultado}")
            
            with col_cancelar:
                if st.button("❌ Cancelar", use_container_width=True):
                    st.session_state.mostrar_formulario_incidencia = False
                    st.rerun()
        
        # Mostrar historial de registros del día
        st.markdown("---")
        st.subheader("📊 Historial de Hoy")
        
        registros_hoy = self.sistema_asistencia.obtener_registros_hoy_usuario(usuario)
        
        if not registros_hoy.empty:
            st.dataframe(
                registros_hoy[['HORA', 'TIPO_REGISTRO']].rename(
                    columns={'HORA': 'Hora', 'TIPO_REGISTRO': 'Tipo de Registro'}
                ),
                use_container_width=True
            )
        else:
            st.info("No hay registros para hoy.")
        
        # Botón para cerrar sesión
        st.markdown("---")
        if st.button("🚪 Cerrar Sesión", use_container_width=True):
            st.session_state.usuario_autenticado = None
            st.session_state.numero_economico = None
            st.session_state.modo = "login"
            st.session_state.mostrar_formulario_incidencia = False
            st.rerun()

    def ejecutar(self):
        """Ejecuta la aplicación principal"""
        # Inicializar estado de sesión
        if 'modo' not in st.session_state:
            st.session_state.modo = None
        if 'usuario_autenticado' not in st.session_state:
            st.session_state.usuario_autenticado = None
        if 'mostrar_formulario_incidencia' not in st.session_state:
            st.session_state.mostrar_formulario_incidencia = False
        
        # Mostrar la interfaz según el modo actual
        if st.session_state.modo is None:
            self.mostrar_seleccion_modo()
        elif st.session_state.modo == "registro":
            self.registrar_usuario()
        elif st.session_state.modo == "login":
            self.mostrar_login()
        elif st.session_state.modo == "asistencia" and st.session_state.usuario_autenticado:
            self.mostrar_sistema_asistencia()
        else:
            st.session_state.modo = None
            st.rerun()

# Ejecutar la aplicación
if __name__ == "__main__":
    app = SistemaEnfermeria()
    app.ejecutar()
