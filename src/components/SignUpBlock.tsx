import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardFooter,
    CardTitle,
} from "@/components/ui/card";
import { useState } from "react";
import { Eye, EyeOff } from "lucide-react";

interface SignUpFormData {
    name: string;
    email: string;
    password: string;
    confirmPassword: string;
}

interface FormErrors {
    name?: string;
    email?: string;
    password?: string;
    confirmPassword?: string;
    general?: string;
}

interface SignUpBlockProps {
    onNavigate: (view: 'login') => void;
}

const SignUpBlock = ({ onNavigate }: SignUpBlockProps) => {
    const [formData, setFormData] = useState<SignUpFormData>({
        name: "",
        email: "",
        password: "",
        confirmPassword: "",
    });
    const [errors, setErrors] = useState<FormErrors>({});
    const [isLoading, setIsLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);

    const validateForm = (): boolean => {
        const newErrors: FormErrors = {};

        if (!formData.name.trim()) {
            newErrors.name = "Name is required";
        }

        if (!formData.email.trim()) {
            newErrors.email = "Email is required";
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
            newErrors.email = "Please enter a valid email address";
        }

        if (!formData.password) {
            newErrors.password = "Password is required";
        } else if (formData.password.length < 8) {
            newErrors.password = "Password must be at least 8 characters";
        }

        if (formData.password !== formData.confirmPassword) {
            newErrors.confirmPassword = "Passwords do not match";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleInputChange = (
        field: keyof SignUpFormData,
        value: string
    ) => {
        setFormData((prev) => ({
            ...prev,
            [field]: value,
        }));

        if (errors[field]) {
            setErrors((prev) => ({
                ...prev,
                [field]: undefined,
            }));
        }
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) return;

        setIsLoading(true);
        setErrors({});

        // 🔹 Simulate a fake request
        setTimeout(() => {
            console.log("Form submitted:", formData);
            alert("Account created successfully (demo only)");
            onNavigate('login');
            setIsLoading(false);
        }, 1000);
    };

    return (
        <Card className="w-full max-w-[400px] mx-auto flex flex-col gap-6 bg-zinc-950 border-zinc-800 text-zinc-100 shadow-xl">
            <CardHeader className="text-center space-y-2 pb-2">
                <CardTitle className="text-2xl font-bold tracking-tight text-white">Create Account</CardTitle>
                <CardDescription className="text-zinc-400">Enter your details to get started</CardDescription>
            </CardHeader>

            <form onSubmit={handleSubmit} className="flex flex-col gap-6">
                <CardContent className="flex flex-col gap-4">
                    {errors.general && (
                        <div className="p-3 text-sm text-red-500 bg-red-500/10 border border-red-500/20 rounded-md">
                            {errors.general}
                        </div>
                    )}

                    <div className="flex flex-col gap-2">
                        <Label htmlFor="name" className="text-zinc-200 font-medium">Name</Label>
                        <Input
                            id="name"
                            type="text"
                            placeholder="John Doe"
                            className="bg-zinc-900 border-zinc-700 text-white placeholder:text-zinc-500 focus-visible:ring-blue-600 focus-visible:border-blue-600"
                            value={formData.name}
                            onChange={(e) => handleInputChange("name", e.target.value)}
                            disabled={isLoading}
                        />
                        {errors.name && (
                            <p className="text-sm text-red-500">{errors.name}</p>
                        )}
                    </div>

                    <div className="flex flex-col gap-2">
                        <Label htmlFor="email" className="text-zinc-200 font-medium">Email</Label>
                        <Input
                            id="email"
                            type="email"
                            placeholder="john.doe@example.com"
                            className="bg-zinc-900 border-zinc-700 text-white placeholder:text-zinc-500 focus-visible:ring-blue-600 focus-visible:border-blue-600"
                            value={formData.email}
                            onChange={(e) => handleInputChange("email", e.target.value)}
                            disabled={isLoading}
                        />
                        {errors.email && (
                            <p className="text-sm text-red-500">{errors.email}</p>
                        )}
                    </div>

                    <div className="flex flex-col gap-2">
                        <Label htmlFor="password" className="text-zinc-200 font-medium">Password</Label>
                        <div className="relative">
                            <Input
                                id="password"
                                type={showPassword ? "text" : "password"}
                                placeholder="Create a password"
                                className="bg-zinc-900 border-zinc-700 text-white placeholder:text-zinc-500 pr-10 focus-visible:ring-blue-600 focus-visible:border-blue-600"
                                value={formData.password}
                                onChange={(e) => handleInputChange("password", e.target.value)}
                                disabled={isLoading}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-300 transition-colors"
                            >
                                {showPassword ? (
                                    <EyeOff className="h-4 w-4" />
                                ) : (
                                    <Eye className="h-4 w-4" />
                                )}
                            </button>
                        </div>
                        {errors.password && (
                            <p className="text-sm text-red-500">{errors.password}</p>
                        )}
                    </div>

                    <div className="flex flex-col gap-2">
                        <Label htmlFor="confirmPassword" className="text-zinc-200 font-medium">Confirm Password</Label>
                        <div className="relative">
                            <Input
                                id="confirmPassword"
                                type={showConfirmPassword ? "text" : "password"}
                                placeholder="Confirm your password"
                                className="bg-zinc-900 border-zinc-700 text-white placeholder:text-zinc-500 pr-10 focus-visible:ring-blue-600 focus-visible:border-blue-600"
                                value={formData.confirmPassword}
                                onChange={(e) => handleInputChange("confirmPassword", e.target.value)}
                                disabled={isLoading}
                            />
                            <button
                                type="button"
                                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-300 transition-colors"
                            >
                                {showConfirmPassword ? (
                                    <EyeOff className="h-4 w-4" />
                                ) : (
                                    <Eye className="h-4 w-4" />
                                )}
                            </button>
                        </div>
                        {errors.confirmPassword && (
                            <p className="text-sm text-red-500">{errors.confirmPassword}</p>
                        )}
                    </div>

                </CardContent>

                <CardFooter className="flex flex-col gap-6 pt-0">
                    <Button
                        type="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold h-11 transition-all duration-200"
                        disabled={isLoading}
                    >
                        {isLoading ? "Creating Account..." : "Sign Up"}
                    </Button>

                    <div className="text-center">
                        <p className="text-sm text-zinc-400">
                            Already have an account?{" "}
                            <button
                                type="button"
                                onClick={() => onNavigate('login')}
                                className="text-white hover:underline font-medium transition-colors"
                            >
                                Sign In
                            </button>
                        </p>
                    </div>
                </CardFooter>
            </form>
        </Card>
    );
};

export default SignUpBlock;
