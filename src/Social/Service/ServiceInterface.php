<?php
namespace CakeDC\Users\Social\Service;


use Cake\Http\ServerRequest;

interface ServiceInterface
{
    /**
     * Check if we are at getUserStep, meaning, we received a callback from provider.
     *
     * @param \Cake\Http\ServerRequest $request Request object.
     * @return bool
     */
    public function isGetUserStep(ServerRequest $request): bool;

    /**
     * Get a authentication url for user
     *
     * @param \Cake\Http\ServerRequest $request Request object.
     * @return string
     */
    public function getAuthorizationUrl(ServerRequest $request);

    /**
     * Get a user in social provider
     *
     * @param \Cake\Http\ServerRequest $request Request object.
     * @return array
     */
    public function getUser(ServerRequest $request): array;

}