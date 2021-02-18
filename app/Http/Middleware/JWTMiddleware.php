<?php

namespace App\Http\Middleware;

use Closure;
use JWTAuth;
use Illuminate\Http\Request;
use Illuminate\Http\RedirectResponse;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

class JWTMiddleware 
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    { 
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Exception $e) {
            if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException) {
                return response()->json(['status' => 'Token is invalid', 'code' => '01'], 401);
            } else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException) {
                try {
                    $refreshed = JWTAuth::refresh(JWTAuth::getToken());
                    $setTokenuser = JWTAuth::setToken($refreshed)->toUser();

                    // return response()->json([
                    //     'status' => 'expired_token', 
                    //     'new_token' => $refreshed
                    // ], 200);
                    header('X-New-Token: ' . $refreshed);
                    return $next($request);
                } catch (JWTException $e) {
                    return response()->json(['status' => 'Whoops, there was some problem with your token', 'code' => '01'], 401);
                } catch (\Tymon\JWTAuth\Exceptions\TokenBlacklistedException $e) {
                    return response()->json(['status' => 'Token has been blacklisted', 'code' => '01'], 401);
                }
            } else {
                return response()->json(['status' => 'Authorization token not found', 'code' => '01'], 401);
            }
        }

        return $next($request);
    }
}
