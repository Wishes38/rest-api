import { Controller, Post, Body, Request, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('login')
    async login(@Body() body: { email: string; password: string }) {
        const user = await this.authService.validateUser(body.email, body.password);
        return this.authService.login(user);
    }

    @Post('logout')
    async logout(@Request() req) {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            throw new UnauthorizedException('No token provided');
        }

        const response = await this.authService.logout(token);
        return response;
    }

    @UseGuards(JwtAuthGuard)
    @Post('refresh-token')
    async refreshToken(
        @Request() req,
        @Body('refreshToken') refreshToken: string,
    ) {
        const userId = req.user.userId;
        if (!refreshToken) {
            throw new UnauthorizedException('No refresh token provided');
        }

        return this.authService.refreshToken(userId, refreshToken);
    }
}
