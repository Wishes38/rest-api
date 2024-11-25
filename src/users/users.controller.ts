import { BadRequestException, Body, Controller, Get, Post, UseGuards, Request, Param, NotFoundException } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { JwtBlacklistGuard } from '../auth/guards/jwt-blacklist.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('users')
@UseGuards(JwtAuthGuard, JwtBlacklistGuard, RolesGuard)
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Post('register')
    async register(
        @Body() body: { email: string; password: string; roles?: string[] },
    ) {
        const { email, password, roles } = body;

        const existingUser = await this.usersService.findUserByEmail(email);
        if (existingUser) {
            throw new BadRequestException('User already exists');
        }

        return this.usersService.createUser(email, password, roles);
    }

    @Roles('user', 'admin')
    @Get('my-profile')
    getUserProfile(@Request() req) {
        return { message: 'Welcome User', user: req.user };
    }

    @Roles('admin')
    @Get('profile')
    getAdminProfile(@Request() req) {
        return { message: 'Welcome Admin', user: req.user };
    }

    @Post('request-password-reset')
    async requestPasswordReset(@Body('email') email: string) {
        console.log(`Password reset requested for email: ${email}`);
        await this.usersService.requestPasswordReset(email);
        return { message: 'Password reset link has been sent to your email.' };
    }

    @UseGuards()
    @Get('reset-password/:token')
    async validateResetToken(@Param('token') token: string) {
        const user = await this.usersService.findUserByResetToken(token);

        if (!user) {
            throw new NotFoundException('Invalid or expired token');
        }

        return { message: 'Token is valid' };
    }

    @UseGuards()
    @Post('reset-password/:token')
    async resetPassword(
        @Param('token') token: string,
        @Body('newPassword') newPassword: string,
    ) {
        await this.usersService.resetPassword(token, newPassword);
        return { message: 'Your password has been reset successfully.' };
    }
}
