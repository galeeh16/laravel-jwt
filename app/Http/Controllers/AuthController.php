<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware(['jwt'], ['except' => ['login', 'register']]);
    }

    public function register(Request $request)
    {
    	$validator = \Validator::make($request->all(), [
    		'email' => 'required|email|unique:users,email',
    		'name' => 'required|string:min:3|max:50',
    		'password' => 'required|string|min:6:max:20',
    		'password_confirmation' => 'required|string|same:password'
    	]);

    	if($validator->fails())
    		return response()->json($validator->messages(), 400);

    	$user = User::create(array_merge(
    		$validator->validated(),
    		['password' => bcrypt($request->password)]
    	));

    	return response()->json(['message' => 'Success created user', 'data' => $user], 201);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        // return $this->respondWithToken(auth()->refresh());
        return response()->json([
            'new_token' => auth()->refresh(),
            'token_type' => 'bearer',
            'status' => 'expired_token',
            'expires_in' => auth()->factory()->getTTL() * 60
        ], 200);
    }

    public function checkToken() 
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Exception $e) {
            if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException) {
                return response()->json(['status' => 'Token is invalid', 'code' => '01'], 401);
            } else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException) {
                try {
                    $refreshed = JWTAuth::refresh(JWTAuth::getToken());
                    $setTokenuser = JWTAuth::setToken($refreshed)->user();
                    return response()->json([
                        'status' => 'expired_token', 
                        'new_token' => $refreshed
                    ], 200);
                } catch (JWTException $e) {
                    return response()->json(['status' => 'Whoops, there was some problem with your token', 'code' => '01'], 401);
                } catch (\Tymon\JWTAuth\Exceptions\TokenBlacklistedException $e) {
                    return response()->json(['status' => 'Token has been blacklisted', 'code' => '01'], 401);
                }
            } else {
                return response()->json(['status' => 'Authorization token not found', 'code' => '01'], 401);
            }
        }
        return response()->json(true, 200);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ], 200);
    }
}