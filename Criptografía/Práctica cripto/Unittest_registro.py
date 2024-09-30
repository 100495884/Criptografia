import unittest
from unittest.mock import patch
from script_registro import registrar_usuario, autenticar_usuario, ValidationError

class TestRegistroInicioSesion(unittest.TestCase):
    def setUp(self):
        self.nombre_usuario_valido = 'usuario_valido'
        self.password_valida = 'password_valida'
        self.nombre_usuario_existente = 'usuario_existente'
        self.password_existente = 'password_existente'
        self.nombre_usuario_inexistente = 'usuario_inexistente'
        self.password_incorrecta = 'password_incorrecta'

    @patch('script_registro.cargar_usuarios')
    @patch('script_registro.guardar_usuarios')
    def test_registro_exitoso(self, mock_guardar_usuarios, mock_cargar_usuarios):
        mock_cargar_usuarios.return_value = {}
        self.assertTrue(registrar_usuario(self.nombre_usuario_valido, self.password_valida))
        mock_guardar_usuarios.assert_called_once()

    @patch('script_registro.cargar_usuarios')
    def test_registro_fallido_nombre_usuario_existente(self, mock_cargar_usuarios):
        mock_cargar_usuarios.return_value = {self.nombre_usuario_existente: {}}
        with self.assertRaises(ValidationError):
            registrar_usuario(self.nombre_usuario_existente, self.password_valida)

    @patch('script_registro.cargar_usuarios')
    def test_registro_fallido_password_existente(self, mock_cargar_usuarios):
        mock_cargar_usuarios.return_value = {self.nombre_usuario_valido: {'hashed_password': self.password_existente}}
        with self.assertRaises(ValidationError):
            registrar_usuario(self.nombre_usuario_valido, self.password_existente)

    @patch('script_registro.cargar_usuarios')
    def test_inicio_sesion_exitoso(self, mock_cargar_usuarios):
        mock_cargar_usuarios.return_value = {self.nombre_usuario_valido: {'hashed_password': self.password_valida}}
        with patch('builtins.input', side_effect=[self.nombre_usuario_valido, '1', self.password_valida, '1', '1']):
            self.assertTrue(autenticar_usuario())

    @patch('script_registro.cargar_usuarios')
    def test_inicio_sesion_fallido_nombre_usuario_inexistente(self, mock_cargar_usuarios):
        mock_cargar_usuarios.return_value = {}
        with patch('builtins.input', side_effect=[self.nombre_usuario_inexistente, self.password_valida]):
            self.assertFalse(autenticar_usuario())

    @patch('script_registro.cargar_usuarios')
    def test_inicio_sesion_fallido_password_incorrecta(self, mock_cargar_usuarios):
        mock_cargar_usuarios.return_value = {self.nombre_usuario_valido: {'hashed_password': self.password_valida}}
        with patch('builtins.input', side_effect=[self.nombre_usuario_valido, self.password_incorrecta]):
            self.assertFalse(autenticar_usuario())

if __name__ == '__main__':
    unittest.main()