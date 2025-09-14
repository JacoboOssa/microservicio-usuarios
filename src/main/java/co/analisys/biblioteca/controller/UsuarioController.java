package co.analisys.biblioteca.controller;

import co.analisys.biblioteca.model.Email;
import co.analisys.biblioteca.model.Usuario;
import co.analisys.biblioteca.model.UsuarioId;
import co.analisys.biblioteca.service.UsuarioService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {

    @Autowired
    private UsuarioService usuarioService;

    @Operation(
            summary = "Obtener un usuario por ID",
            description = "Devuelve la información de un usuario específico a partir de su ID. "
                    + "Disponible tanto para bibliotecarios como para usuarios."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario encontrado",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = Usuario.class))),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content),
            @ApiResponse(responseCode = "403", description = "Acceso denegado", content = @Content)
    })
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ROLE_LIBRARIAN', 'ROLE_USER')")
    public Usuario obtenerUsuario(
            @Parameter(description = "ID del usuario a consultar", required = true, example = "USR123")
            @PathVariable String id) {
        return usuarioService.obtenerUsuario(new UsuarioId(id));
    }

    @Operation(
            summary = "Cambiar email de un usuario",
            description = "Permite actualizar la dirección de correo electrónico de un usuario existente. "
                    + "Disponible para bibliotecarios y usuarios."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email actualizado exitosamente"),
            @ApiResponse(responseCode = "400", description = "Formato de email inválido", content = @Content),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content),
            @ApiResponse(responseCode = "403", description = "Acceso denegado", content = @Content)
    })
    @PutMapping("/{id}/email")
    @PreAuthorize("hasAnyRole('ROLE_LIBRARIAN', 'ROLE_USER')")
    public void cambiarEmail(
            @Parameter(description = "ID del usuario al que se le cambiará el email", required = true, example = "USR123")
            @PathVariable String id,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Nuevo email a asignar al usuario",
                    required = true,
                    content = @Content(mediaType = "application/json",
                            examples = {
                                    @ExampleObject(name = "Ejemplo válido", value = "\"usuario@dominio.com\""),
                                    @ExampleObject(name = "Ejemplo inválido", value = "\"usuario_invalido\"")
                            })
            )
            @RequestBody String nuevoEmail) {
        usuarioService.cambiarEmailUsuario(new UsuarioId(id), new Email(nuevoEmail));
    }
}
