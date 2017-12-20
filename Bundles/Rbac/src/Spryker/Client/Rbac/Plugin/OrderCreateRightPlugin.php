<?php


namespace Spryker\Client\Rbac\Plugin;


class OrderCreateRightPlugin implements RbacRightPluginInterface, RbacRightExecutionAwareInterface
{
    const OPTION_CART_GRAND_TOTAL = 1000;

    /**
     * @var array
     */
    protected $config;

    /**
     * @param array $options
     *
     * @return bool
     */
    public function execute(array $options)
    {
        //<common code>
        if (!isset($options[static::OPTION_CART_GRAND_TOTAL])) {
            return false;
        }

        if (!isset($this->config[static::OPTION_CART_GRAND_TOTAL])) {
            return false;
        }
        //</common code>

        if ($options[static::OPTION_CART_GRAND_TOTAL] > $this->config[static::OPTION_CART_GRAND_TOTAL]) {
            return false;
        }

        return true;
    }

    /**
     * @param array $config
     */
    public function configure(array $config)
    {
        $this->config = $config;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return 'order.create';
    }
}