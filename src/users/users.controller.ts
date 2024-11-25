import { BadRequestException, Body, Controller, Get, Post, UseGuards, Request, Param, NotFoundException } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { JwtBlacklistGuard } from '../auth/guards/jwt-blacklist.guard';
import { Roles } from '../auth/roles.decorator';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { RegisterDto } from './dto/register.dto';

@ApiTags('Users')
@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @ApiOperation({ summary: 'Register a new user' })
    @ApiBody({ type: RegisterDto })
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

    @ApiOperation({ summary: 'User Profile Page' })
    @UseGuards(JwtAuthGuard, JwtBlacklistGuard, RolesGuard)
    @ApiBearerAuth()
    @Roles('user', 'admin')
    @Get('my-profile')
    getUserProfile(@Request() req) {
        return { message: 'Welcome User', user: req.user };
    }

    @ApiOperation({ summary: 'Admin Profile Page' })
    @UseGuards(JwtAuthGuard, JwtBlacklistGuard, RolesGuard)
    @ApiBearerAuth()
    @Roles('admin')
    @Get('profile')
    getAdminProfile(@Request() req) {
        return { message: 'Welcome Admin', user: req.user };
    }

    @ApiOperation({ summary: 'Access token and email required' })
    @UseGuards(JwtAuthGuard, JwtBlacklistGuard, RolesGuard)
    @ApiBearerAuth()
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                email: {
                    type: 'string',
                    example: 'serkanozdemir38080@gmail.com',
                    description: 'The email address to send the reset link to',
                },
            },
        },
    })
    @Post('request-password-reset')
    async requestPasswordReset(@Body('email') email: string) {
        console.log(`Password reset requested for email: ${email}`);
        await this.usersService.requestPasswordReset(email);
        return { message: 'Password reset link has been sent to your email.' };
    }

    @ApiOperation({ summary: 'Validate password reset token' })
    @Get('reset-password/:token')
    async validateResetToken(@Param('token') token: string) {
        const user = await this.usersService.findUserByResetToken(token);

        if (!user) {
            throw new NotFoundException('Invalid or expired token');
        }

        return { message: 'Token is valid' };
    }

    @ApiOperation({ summary: 'Reset password' })
    @ApiBody({ schema: { example: { newPassword: "newpassword123" } } })
    @Post('reset-password/:token')
    async resetPassword(
        @Param('token') token: string,
        @Body('newPassword') newPassword: string,
    ) {
        await this.usersService.resetPassword(token, newPassword);
        return { message: 'Your password has been reset successfully.' };
    }
}
