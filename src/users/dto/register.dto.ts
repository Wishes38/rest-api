import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, MinLength } from 'class-validator';

export class RegisterDto {
    @ApiProperty({ example: 'user@example.com', description: 'User email address' })
    @IsEmail()
    email: string;

    @ApiProperty({ example: 'password123', description: 'User password', minLength: 6 })
    @IsNotEmpty()
    @MinLength(6)
    password: string;

    @ApiProperty({ example: ['user'], description: 'Roles assigned to the user', required: false })
    @IsOptional()
    roles?: string[];
}
